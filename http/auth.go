package http

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	verifier "github.com/okta/okta-jwt-verifier-golang"
	"github.com/patrickmn/go-cache"
)

type key string

const (
	// IDTokenKey is the key used for id_token in session store and context injection
	IDTokenKey key = "id_token"

	sessionName                  = "okta-session"
	sessionIDTokenKey     string = string(IDTokenKey)
	sessionAccessTokenKey string = "access_token"
	sessionNonceKey       string = "nonce"
	stateExpiration              = 5 * time.Minute
)

// ErrorWriter is a function that is used to write error responses.
type ErrorWriter func(w http.ResponseWriter, r *http.Request, err error, status int)

// AuthHandler manages okta based authentication.
type AuthHandler struct {
	sessionStore *sessions.CookieStore
	clientID     string
	clientSecret string
	issuer       string
	redirectURI  string
	appendPath   bool
	errorWriter  ErrorWriter

	redirectURIstate *cache.Cache
}

// NewAuthHandler constructs a new Okta OAuth handler.
func NewAuthHandler(sessionKey []byte, clientID, clientSecret, issuer, redirectURI string, appendPath bool, errorWriter func(w http.ResponseWriter, r *http.Request, err error, status int)) *AuthHandler {
	return &AuthHandler{
		sessionStore:     sessions.NewCookieStore(sessionKey),
		clientID:         clientID,
		clientSecret:     clientSecret,
		issuer:           issuer,
		errorWriter:      errorWriter,
		redirectURI:      redirectURI,
		appendPath:       appendPath,
		redirectURIstate: cache.New(stateExpiration, stateExpiration),
	}
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

		state := uuid.New().String()
		if h.appendPath {
			h.redirectURIstate.Set(state, r.URL.Path, 0)
		}

		q := r.URL.Query()
		q.Add("client_id", h.clientID)
		q.Add("response_type", "code")
		q.Add("response_mode", "query")
		q.Add("scope", "openid profile email")
		q.Add("redirect_uri", h.redirectURI)
		q.Add("state", state)
		q.Add("nonce", nonce)

		session, err := h.sessionStore.Get(r, sessionName)
		if err != nil {
			h.errorWriter(w, r, err, http.StatusInternalServerError)
			return
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

	session.Values[sessionIDTokenKey] = exchange.IDToken
	session.Values[sessionAccessTokenKey] = exchange.AccessToken
	err = session.Save(r, w)
	if err != nil {
		h.errorWriter(w, r, err, http.StatusInternalServerError)
		return
	}

	path := "/"
	state := r.URL.Query().Get("state")
	if state != "" {
		if p, ok := h.redirectURIstate.Get(state); ok {
			if pp, ok := p.(string); ok {
				path = "/" + strings.TrimLeft(pp, "/")
			}
			h.redirectURIstate.Delete(state)
		}
	}

	http.Redirect(w, r, path, http.StatusFound)
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
