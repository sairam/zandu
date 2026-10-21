package forwarder

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Runtime holds state shared by the proxy and admin handlers that is not
// part of the configuration: secret resolution, OAuth2 access tokens for
// upstreams and JSON Web Key Sets of trusted issuers.
type Runtime struct {
	Secrets *Secrets
	// HTTPClient is used for token endpoints and JWKS documents.
	HTTPClient *http.Client

	oauthMu sync.Mutex
	oauth   map[string]cachedToken
	jwks    jwksCache
}

type cachedToken struct {
	token  string
	expiry time.Time
}

// NewRuntime returns a runtime that resolves secrets with s.
func NewRuntime(s *Secrets) *Runtime {
	return &Runtime{
		Secrets:    s,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		oauth:      map[string]cachedToken{},
	}
}

// upstreamCredentials are the resolved values added to a forwarded request.
type upstreamCredentials struct {
	query   map[string]string
	headers map[string]string
}

// credentials resolves everything the upstream needs for one request.
func (rt *Runtime) credentials(ctx context.Context, up *Upstream) (*upstreamCredentials, error) {
	c := &upstreamCredentials{query: map[string]string{}, headers: map[string]string{}}
	for k, v := range up.Inject.Query {
		rv, err := rt.Secrets.Resolve(ctx, v)
		if err != nil {
			return nil, fmt.Errorf("query %q: %w", k, err)
		}
		c.query[k] = rv
	}
	for k, v := range up.Inject.Headers {
		rv, err := rt.Secrets.Resolve(ctx, v)
		if err != nil {
			return nil, fmt.Errorf("header %q: %w", k, err)
		}
		c.headers[http.CanonicalHeaderKey(k)] = rv
	}
	a := up.Auth
	if a == nil {
		return c, nil
	}
	switch a.Type {
	case UpstreamAuthBasic:
		user, err := rt.Secrets.Resolve(ctx, a.Username)
		if err != nil {
			return nil, fmt.Errorf("auth username: %w", err)
		}
		pass, err := rt.Secrets.Resolve(ctx, a.Password)
		if err != nil {
			return nil, fmt.Errorf("auth password: %w", err)
		}
		r := &http.Request{Header: http.Header{}}
		r.SetBasicAuth(user, pass)
		c.headers["Authorization"] = r.Header.Get("Authorization")
	case UpstreamAuthBearer:
		tok, err := rt.Secrets.Resolve(ctx, a.Token)
		if err != nil {
			return nil, fmt.Errorf("auth token: %w", err)
		}
		c.headers["Authorization"] = "Bearer " + tok
	case UpstreamAuthClientCredentials:
		tok, err := rt.clientCredentialsToken(ctx, a)
		if err != nil {
			return nil, fmt.Errorf("oauth2 token: %w", err)
		}
		c.headers["Authorization"] = "Bearer " + tok
	}
	return c, nil
}

func oauthKey(a *UpstreamAuth) string {
	return strings.Join([]string{a.TokenURL, a.ClientID, strings.Join(a.Scopes, " "), a.Audience}, "\x00")
}

// clientCredentialsToken returns a cached access token, fetching a new one
// from the token endpoint shortly before the current one expires.
func (rt *Runtime) clientCredentialsToken(ctx context.Context, a *UpstreamAuth) (string, error) {
	key := oauthKey(a)
	rt.oauthMu.Lock()
	defer rt.oauthMu.Unlock()
	if t, ok := rt.oauth[key]; ok && time.Now().Before(t.expiry) {
		return t.token, nil
	}

	id, err := rt.Secrets.Resolve(ctx, a.ClientID)
	if err != nil {
		return "", err
	}
	secret, err := rt.Secrets.Resolve(ctx, a.ClientSecret)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	if len(a.Scopes) > 0 {
		form.Set("scope", strings.Join(a.Scopes, " "))
	}
	if a.Audience != "" {
		form.Set("audience", a.Audience)
	}
	if a.ClientAuthInBody {
		form.Set("client_id", id)
		form.Set("client_secret", secret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if !a.ClientAuthInBody {
		req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	}
	resp, err := rt.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %s", resp.Status)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("token response has no access_token")
	}
	lifetime := 5 * time.Minute
	if out.ExpiresIn > 0 {
		lifetime = time.Duration(out.ExpiresIn) * time.Second
	}
	// Refresh early so a token never expires in flight.
	lifetime -= min(30*time.Second, lifetime/2)
	rt.oauth[key] = cachedToken{token: out.AccessToken, expiry: time.Now().Add(lifetime)}
	return out.AccessToken, nil
}

// invalidateToken drops a cached access token the upstream rejected.
func (rt *Runtime) invalidateToken(a *UpstreamAuth) {
	if a == nil || a.Type != UpstreamAuthClientCredentials {
		return
	}
	rt.oauthMu.Lock()
	delete(rt.oauth, oauthKey(a))
	rt.oauthMu.Unlock()
}
