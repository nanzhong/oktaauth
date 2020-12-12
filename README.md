# Okta Auth

Small and simple drop in utils for handling Okta auth.

## OAuth handler

This handler is an easy way to put Okta OAuth in front of endpoints.

```go

var (
    sessionKey   []byte
    clientID     string
    clientSecret string
    issuer       string
    redirectURI  string
    preservePath bool
    errorWriter  func(w http.ResponseWriter, r *http.Request, err error, status int)
)

// ...

oaHandler := NewAuthHandler(sessionKey, clientID, clientSecret, issuer, redirectURI, WithPreservePath(true), WithErrorWriter(errorWriter))
http.HandleFunc("/oauth/callback", oaHandler.AuthCodeCallbackHandler)
http.HandleFunc("/", oaHandler.Ensure(realRouteHandler))
http.HandleFunc("/logout", oaHandler.ClearSessionHandler)
```
