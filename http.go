package oktaauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	verifier "github.com/okta/okta-jwt-verifier-golang"
)

type key string

const (
	// IDTokenKey is the key used for id_token in session store and context injection
	IDTokenKey key = "id_token"

	sessionName            = "okta-session"
	sessionIDTokenKey      = string(IDTokenKey)
	sessionAccessTokenKey  = "access_token"
	sessionNonceKey        = "nonce"
	sessionRedirectPathKey = "redirect_path"
	sessionSubjectKey      = "sub"
)

// UserInfo encodes user information.
// TODO this is a subset of the info fields. This could be augmented if
// documentation around the full set can be found.
type UserInfo struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
}

// ErrorWriter is a function that is used to write error responses.
type ErrorWriter func(w http.ResponseWriter, r *http.Request, err error, status int)

// Option is a function for configuring an AuthHandler.
type Option func(h *AuthHandler)

// WithErrorWriter is an Option for configuring a custom error writer.
func WithErrorWriter(w ErrorWriter) Option {
	return func(h *AuthHandler) {
		h.errorWriter = w
	}
}

// WithPreservePath is an Option for configuring preserving path after login.
func WithPreservePath(p bool) Option {
	return func(h *AuthHandler) {
		h.preservePath = p
	}
}

// AuthHandler manages okta based authentication.
type AuthHandler struct {
	sessionStore *sessions.CookieStore
	clientID     string
	clientSecret string
	issuer       string
	redirectURI  string
	preservePath bool
	errorWriter  ErrorWriter

	mu          sync.Mutex
	userInfoMap map[string]*UserInfo
}

var (
	// ErrInvalidConfig is the error that will be wrapped and returned when a new
	// AuthHandler is attempted to be created with invalid configuration.
	ErrInvalidConfig = errors.New("invalid okta configuration")

	// ErrInvalidSession is the error that will be wrapped and return when an
	// invalid session is being used.
	ErrInvalidSession = errors.New("invalid okta session")
)

func init() {
	gob.Register(&UserInfo{})
}

// NewAuthHandler constructs a new Okta OAuth handler.
func NewAuthHandler(sessionKey []byte, clientID, clientSecret, issuer, redirectURI string, opts ...Option) (*AuthHandler, error) {
	if len(sessionKey) == 0 {
		return nil, fmt.Errorf("missing session key: %w", ErrInvalidConfig)
	}
	if len(clientID) == 0 {
		return nil, fmt.Errorf("missing client id: %w", ErrInvalidConfig)
	}
	if len(clientSecret) == 0 {
		return nil, fmt.Errorf("missing client secret: %w", ErrInvalidConfig)
	}
	if len(issuer) == 0 {
		return nil, fmt.Errorf("missing issuer: %w", ErrInvalidConfig)
	}
	if len(redirectURI) == 0 {
		return nil, fmt.Errorf("missing redirect uri: %w", ErrInvalidConfig)
	}

	h := &AuthHandler{
		sessionStore: sessions.NewCookieStore(sessionKey),
		clientID:     clientID,
		clientSecret: clientSecret,
		issuer:       issuer,
		redirectURI:  redirectURI,
		userInfoMap:  make(map[string]*UserInfo),

		// Defaults.
		errorWriter: func(w http.ResponseWriter, r *http.Request, err error, status int) {
			w.WriteHeader(status)
			fmt.Fprintf(w, "%d: %s", status, err)
		},
		preservePath: true,
	}

	for _, opt := range opts {
		opt(h)
	}
	return h, nil
}

// ConfigureErrorWriter allows configuring an error writer for an existing AuthHandler.
func (h *AuthHandler) ConfigureErrorWriter(w ErrorWriter) {
	h.errorWriter = w
}

func (h *AuthHandler) isAuthenticated(r *http.Request) (bool, *verifier.Jwt) {
	session, err := h.sessionStore.Get(r, sessionName)
	if err != nil ||
		session.Values[sessionIDTokenKey] == nil || session.Values[sessionIDTokenKey] == "" ||
		session.Values[sessionNonceKey] == nil || session.Values[sessionNonceKey] == "" {
		return false, nil
	}

	nonce, _ := session.Values[sessionNonceKey].(string)
	idToken, _ := session.Values[sessionIDTokenKey].(string)

	token, err := h.verifyToken(idToken, nonce)
	if err != nil {
		return false, nil
	}

	return true, token
}

// Ensure wraps an http.Handler and ensure the routes are authed via okta.
func (h *AuthHandler) Ensure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isAuthenticated, token := h.isAuthenticated(r); isAuthenticated {
			r = r.WithContext(context.WithValue(r.Context(), IDTokenKey, token))
			next.ServeHTTP(w, r)
			return
		}

		nonce, err := generateNonce()
		if err != nil {
			log.Printf("failed to start okta auth: %s", err)
			h.errorWriter(w, r, err, http.StatusInternalServerError)
			return
		}

		q := r.URL.Query()
		q.Add("client_id", h.clientID)
		q.Add("response_type", "code")
		q.Add("response_mode", "query")
		q.Add("scope", "openid profile email")
		q.Add("redirect_uri", h.redirectURI)
		q.Add("state", uuid.New().String())
		q.Add("nonce", nonce)

		session, err := h.sessionStore.Get(r, sessionName)
		if err != nil {
			h.errorWriter(w, r, err, http.StatusInternalServerError)
			return
		}

		if h.preservePath {
			session.Values[sessionRedirectPathKey] = r.URL.Path
		}

		session.Values[sessionNonceKey] = nonce
		err = session.Save(r, w)
		if err != nil {
			h.errorWriter(w, r, err, http.StatusInternalServerError)
			return
		}

		redirectPath := h.issuer + "/v1/authorize?" + q.Encode()
		http.Redirect(w, r, redirectPath, http.StatusFound)
	})
}

// AuthCodeCallbackHandler is the callback handler for the OAuth flow.
func (h *AuthHandler) AuthCodeCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Make sure the code was provided
	if r.URL.Query().Get("code") == "" {
		h.errorWriter(w, r, errors.New("missing auth code"), http.StatusInternalServerError)
		return
	}

	exchange, err := h.exchangeCode(r.URL.Query().Get("code"), r)
	if err != nil {
		h.errorWriter(w, r, err, http.StatusInternalServerError)
		return
	}

	session, err := h.sessionStore.Get(r, sessionName)
	if err != nil {
		h.errorWriter(w, r, err, http.StatusInternalServerError)
		return
	}

	var nonce string
	// treat missing or invalid nonce as ""
	value := session.Values[sessionNonceKey]
	nonce, _ = value.(string)
	_, err = h.verifyToken(exchange.IDToken, nonce)
	if err != nil {
		h.errorWriter(w, r, err, http.StatusForbidden)
		return
	}

	path := "/"
	if p, ok := session.Values[sessionRedirectPathKey]; ok {
		pp, _ := p.(string)
		path = "/" + strings.TrimLeft(pp, "/")
		delete(session.Values, sessionRedirectPathKey)
	}

	session.Values[sessionIDTokenKey] = exchange.IDToken
	session.Values[sessionAccessTokenKey] = exchange.AccessToken

	userInfo, err := h.loadUserInfo(exchange.AccessToken)
	if err != nil {
		h.errorWriter(w, r, err, http.StatusInternalServerError)
		return
	}
	session.Values[sessionSubjectKey] = userInfo.Subject
	h.mu.Lock()
	defer h.mu.Unlock()
	h.userInfoMap[userInfo.Subject] = userInfo

	err = session.Save(r, w)
	if err != nil {
		h.errorWriter(w, r, err, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, path, http.StatusFound)
}

// ClearSessionHandler clears the okta session.
func (h *AuthHandler) ClearSessionHandler(w http.ResponseWriter, r *http.Request) {
	session, err := h.sessionStore.Get(r, sessionName)
	if err != nil {
		h.errorWriter(w, r, err, http.StatusInternalServerError)
		return
	}
	sub, exists := session.Values[sessionSubjectKey]
	if exists {
		h.mu.Lock()
		defer h.mu.Unlock()
		delete(h.userInfoMap, sub.(string))
	}

	delete(session.Values, "id_token")
	delete(session.Values, "access_token")

	err = session.Save(r, w)
	if err != nil {
		h.errorWriter(w, r, err, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// UserInfo returns info for the user logged into the session.
func (h *AuthHandler) UserInfo(r *http.Request) (*UserInfo, error) {
	session, err := h.sessionStore.Get(r, sessionName)
	if err != nil {
		return nil, fmt.Errorf("missing session: %w", ErrInvalidSession)
	}
	sub, exists := session.Values[sessionSubjectKey]
	if !exists {
		return nil, fmt.Errorf("missing subject: %w", ErrInvalidSession)
	}

	userInfo, exists := h.userInfoMap[sub.(string)]
	if !exists {
		return nil, fmt.Errorf("missing user info: %w", ErrInvalidSession)
	}

	return userInfo, nil
}

func (h *AuthHandler) loadUserInfo(accessToken string) (*UserInfo, error) {
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/userinfo", h.issuer), nil)
	if err != nil {
		return nil, fmt.Errorf("creating user info url: %w", err)
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getting user info: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getting user info: %d", resp.StatusCode)
	}

	m := new(UserInfo)
	err = json.NewDecoder(resp.Body).Decode(m)
	if err != nil {
		return nil, fmt.Errorf("parsing user info: %w", err)
	}

	fmt.Printf("%#v\n", m)

	return m, nil
}

func generateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}

type exchange struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IDToken          string `json:"id_token,omitempty"`
}

func (h *AuthHandler) exchangeCode(code string, r *http.Request) (*exchange, error) {
	authHeader := base64.StdEncoding.EncodeToString(
		[]byte(h.clientID + ":" + h.clientSecret))

	q := r.URL.Query()
	q.Add("grant_type", "authorization_code")
	q.Add("code", code)
	q.Add("redirect_uri", h.redirectURI)

	url := h.issuer + "/v1/token?" + q.Encode()

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("constructing auth code exchange request: %w", err)
	}

	req.Header.Add("Authorization", "Basic "+authHeader)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Connection", "close")
	req.Header.Add("Content-Length", "0")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchanging auth code: %w", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	defer resp.Body.Close()

	var exchange exchange
	err = json.Unmarshal(body, &exchange)
	if err != nil {
		return nil, fmt.Errorf("parsing auth code exchange response: %w", err)
	}

	return &exchange, nil
}

func (h *AuthHandler) verifyToken(token, nonce string) (*verifier.Jwt, error) {
	tv := map[string]string{}
	tv["nonce"] = nonce
	tv["aud"] = h.clientID
	jv := verifier.JwtVerifier{
		Issuer:           h.issuer,
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyIdToken(token)
	if err != nil {
		return nil, fmt.Errorf("verifying token: %w", err)
	}

	if result != nil {
		return result, nil
	}
	return nil, errors.New("token could not be verified")
}
