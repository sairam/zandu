package forwarder

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var b64 = base64.RawURLEncoding

func signJWT(t *testing.T, alg, kid string, key any, claims map[string]any) string {
	t.Helper()
	hdr := map[string]string{"alg": alg, "typ": "JWT"}
	if kid != "" {
		hdr["kid"] = kid
	}
	hb, _ := json.Marshal(hdr)
	cb, _ := json.Marshal(claims)
	signed := b64.EncodeToString(hb) + "." + b64.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signed))
	var sig []byte
	var err error
	switch k := key.(type) {
	case []byte:
		m := hmac.New(sha256.New, k)
		m.Write([]byte(signed))
		sig = m.Sum(nil)
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
	case *ecdsa.PrivateKey:
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, k, digest[:])
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, []byte(signed))
	case nil:
	}
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + b64.EncodeToString(sig)
}

type jwtFixture struct {
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	edKey  ed25519.PrivateKey
	jwks   *httptest.Server
	hits   *atomic.Int32
	proxy  *Proxy
	audit  *AuditLog
	seen   *seenRequest
}

func newJWTFixture(t *testing.T) *jwtFixture {
	t.Helper()
	f := &jwtFixture{hits: &atomic.Int32{}}
	f.rsaKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.ecKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, f.edKey, _ = ed25519.GenerateKey(rand.Reader)
	f.jwks = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
			{"kty": "RSA", "kid": "rsa1", "use": "sig", "n": b64.EncodeToString(f.rsaKey.N.Bytes()), "e": b64.EncodeToString(big.NewInt(int64(f.rsaKey.E)).Bytes())},
			{"kty": "EC", "kid": "ec1", "crv": "P-256", "x": b64.EncodeToString(f.ecKey.X.FillBytes(make([]byte, 32))), "y": b64.EncodeToString(f.ecKey.Y.FillBytes(make([]byte, 32)))},
			{"kty": "OKP", "kid": "ed1", "crv": "Ed25519", "x": b64.EncodeToString(f.edKey.Public().(ed25519.PublicKey))},
			{"kty": "RSA", "kid": "enc", "use": "enc", "n": "AQAB", "e": "AQAB"},
		}})
	}))
	t.Cleanup(f.jwks.Close)

	up, seen := fakeUpstream(t)
	f.seen = seen
	t.Setenv("ZANDU_TEST_HMAC", "hmac-secret")
	store, err := NewMemoryStore(&Config{
		Issuers: []Issuer{
			{Name: "idp", Issuer: "https://idp.example", Audience: []string{"zandu"}, JWKSURL: f.jwks.URL, SubjectClaim: "client_id"},
			{Name: "internal", Issuer: "internal", HMACSecret: "env:ZANDU_TEST_HMAC"},
		},
		Upstreams: []Upstream{{Name: "api", BaseURL: up.URL}},
		Policies:  []Policy{{Name: "all", Upstream: "api", Rules: []Rule{{Effect: EffectAllow}}}},
		Clients: []Client{
			{Name: "svc", TokenHash: HashToken(testToken), Policies: []string{"all"}, Identities: []Identity{
				{Issuer: "idp", Subject: "svc-client"},
				{Issuer: "internal", Subject: "svc"},
			}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.audit = NewAuditLog(5)
	f.proxy = NewProxy(store, f.audit, ProxyOptions{Logger: quietLogger()})
	return f
}

// tamper replaces a token's claims while keeping its header and signature.
func tamper(token string, claims map[string]any) string {
	cb, _ := json.Marshal(claims)
	parts := strings.Split(token, ".")
	return parts[0] + "." + b64.EncodeToString(cb) + "." + parts[2]
}

func withAuth(v string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", v) }
}

func TestClientAuthJWT(t *testing.T) {
	f := newJWTFixture(t)
	now := time.Now().Unix()
	idp := func(extra map[string]any) map[string]any {
		c := map[string]any{"iss": "https://idp.example", "aud": []string{"other", "zandu"}, "client_id": "svc-client", "exp": now + 300}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	internal := map[string]any{"iss": "internal", "sub": "svc", "exp": now + 300}
	secret := []byte("hmac-secret")

	cases := []struct {
		name  string
		token string
		want  int
	}{
		{"RS256 via JWKS", signJWT(t, "RS256", "rsa1", f.rsaKey, idp(nil)), 200},
		{"ES256 via JWKS", signJWT(t, "ES256", "ec1", f.ecKey, idp(nil)), 200},
		{"EdDSA via JWKS", signJWT(t, "EdDSA", "ed1", f.edKey, idp(nil)), 200},
		{"no kid tries all keys", signJWT(t, "RS256", "", f.rsaKey, idp(nil)), 200},
		{"HS256 shared secret", signJWT(t, "HS256", "", secret, internal), 200},
		{"string audience", signJWT(t, "RS256", "rsa1", f.rsaKey, idp(map[string]any{"aud": "zandu"})), 200},
		{"expired", signJWT(t, "RS256", "rsa1", f.rsaKey, idp(map[string]any{"exp": now - 3600})), 401},
		{"no exp", signJWT(t, "HS256", "", secret, map[string]any{"iss": "internal", "sub": "svc"}), 401},
		{"not yet valid", signJWT(t, "RS256", "rsa1", f.rsaKey, idp(map[string]any{"nbf": now + 3600})), 401},
		{"wrong audience", signJWT(t, "RS256", "rsa1", f.rsaKey, idp(map[string]any{"aud": "someone-else"})), 401},
		{"unknown subject", signJWT(t, "RS256", "rsa1", f.rsaKey, idp(map[string]any{"client_id": "nobody"})), 401},
		{"untrusted issuer", signJWT(t, "RS256", "rsa1", f.rsaKey, idp(map[string]any{"iss": "https://evil.example"})), 401},
		{"wrong key", signJWT(t, "HS256", "", []byte("guess"), internal), 401},
		{"alg none", signJWT(t, "none", "", nil, internal), 401},
		{"HS256 against JWKS issuer", signJWT(t, "HS256", "rsa1", []byte("anything"), idp(nil)), 401},
		{"RS256 against HMAC issuer", signJWT(t, "RS256", "rsa1", f.rsaKey, internal), 401},
		{"kid mismatch", signJWT(t, "ES256", "rsa1", f.ecKey, idp(nil)), 401},
		{"tampered claims", tamper(signJWT(t, "RS256", "rsa1", f.rsaKey, idp(nil)), idp(map[string]any{"client_id": "svc-client", "scope": "admin"})), 401},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := do(f.proxy, "GET", "/api/x", "", nil, withAuth("Bearer "+c.token))
			if w.Code != c.want {
				t.Fatalf("status = %d, want %d; audit: %s", w.Code, c.want, f.audit.Recent(1)[0].Reason)
			}
		})
	}
	do(f.proxy, "GET", "/api/x", "", nil, withAuth("Bearer "+cases[0].token))
	if e := f.audit.Recent(1)[0]; e.AuthMethod != AuthJWT || e.Client != "svc" || !e.Allowed {
		t.Errorf("audit entry = %+v", e)
	}
	if f.seen.Header.Get("Authorization") != "" {
		t.Error("client JWT was forwarded upstream")
	}
	// The key set is fetched once and then cached.
	if n := f.hits.Load(); n != 1 {
		t.Errorf("JWKS fetched %d times", n)
	}
}

func TestClientAuthBasicAndHeader(t *testing.T) {
	f := newJWTFixture(t)
	basic := func(u, p string) func(*http.Request) { return func(r *http.Request) { r.SetBasicAuth(u, p) } }
	cases := []struct {
		name   string
		mutate func(*http.Request)
		want   int
		method string
	}{
		{"bearer token", withAuth("Bearer " + testToken), 200, AuthToken},
		{"token header", func(r *http.Request) { r.Header.Set(TokenHeader, testToken) }, 200, AuthToken},
		{"basic", basic("svc", testToken), 200, AuthBasic},
		{"basic wrong user", basic("other", testToken), 401, AuthBasic},
		{"basic wrong password", basic("svc", "zfw_nope"), 401, AuthBasic},
		{"unknown scheme", withAuth("Digest abc"), 401, ""},
		{"opaque bearer", withAuth("Bearer opaque"), 401, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := do(f.proxy, "GET", "/api/x", "", nil, c.mutate)
			if w.Code != c.want {
				t.Fatalf("status = %d, want %d", w.Code, c.want)
			}
			if c.want == 401 && w.Header().Get("WWW-Authenticate") == "" {
				t.Error("missing WWW-Authenticate")
			}
			if got := f.audit.Recent(1)[0].AuthMethod; got != c.method {
				t.Errorf("auth method = %q, want %q", got, c.method)
			}
		})
	}
}

func TestUpstreamAuth(t *testing.T) {
	up, seen := fakeUpstream(t)
	var tokenHits atomic.Int32
	var lastForm atomic.Value
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHits.Add(1)
		r.ParseForm()
		lastForm.Store(r.PostForm)
		id, secret, ok := r.BasicAuth()
		if !ok {
			id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		if id != "cid" || secret != "csecret" || r.PostForm.Get("grant_type") != "client_credentials" {
			http.Error(w, "denied", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at-" + string(rune('0'+tokenHits.Load())), "expires_in": 3600, "token_type": "Bearer"})
	}))
	t.Cleanup(idp.Close)
	t.Setenv("ZANDU_TEST_CSECRET", "csecret")

	newProxy := func(a *UpstreamAuth, inject Inject) *Proxy {
		store, err := NewMemoryStore(&Config{
			Upstreams: []Upstream{{Name: "api", BaseURL: up.URL, Auth: a, Inject: inject}},
			Policies:  []Policy{{Name: "all", Upstream: "api", Rules: []Rule{{Effect: EffectAllow}}}},
			Clients:   []Client{{Name: "bot", TokenHash: HashToken(testToken), Policies: []string{"all"}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return NewProxy(store, NewAuditLog(1), ProxyOptions{Logger: quietLogger()})
	}

	p := newProxy(&UpstreamAuth{Type: UpstreamAuthBasic, Username: "u", Password: "p:w"}, Inject{})
	do(p, "GET", "/api/x", testToken, nil)
	r := &http.Request{Header: seen.Header}
	if u, pw, ok := r.BasicAuth(); !ok || u != "u" || pw != "p:w" {
		t.Errorf("basic = %q %q %v", u, pw, ok)
	}

	p = newProxy(&UpstreamAuth{Type: UpstreamAuthBearer, Token: "env:ZANDU_TEST_CSECRET"}, Inject{Headers: map[string]string{"x-api-version": "2"}})
	do(p, "GET", "/api/x", testToken, nil)
	if got := seen.Header.Get("Authorization"); got != "Bearer csecret" {
		t.Errorf("bearer = %q", got)
	}
	if seen.Header.Get("X-Api-Version") != "2" {
		t.Error("injected header missing")
	}

	cc := &UpstreamAuth{Type: UpstreamAuthClientCredentials, TokenURL: idp.URL, ClientID: "cid", ClientSecret: "env:ZANDU_TEST_CSECRET", Scopes: []string{"dns:read", "dns:write"}, Audience: "api"}
	p = newProxy(cc, Inject{})
	for i := 0; i < 3; i++ {
		if w := do(p, "GET", "/api/x", testToken, nil); w.Code != 200 {
			t.Fatalf("status = %d: %s", w.Code, w.Body)
		}
	}
	if seen.Header.Get("Authorization") != "Bearer at-1" || tokenHits.Load() != 1 {
		t.Fatalf("auth = %q, token fetches = %d", seen.Header.Get("Authorization"), tokenHits.Load())
	}
	form := lastForm.Load().(url.Values)
	if form["scope"][0] != "dns:read dns:write" || form["audience"][0] != "api" {
		t.Errorf("token request form = %v", form)
	}

	// A 401 from the upstream discards the cached token.
	p.opts.Runtime.invalidateToken(cc)
	do(p, "GET", "/api/x", testToken, nil)
	if seen.Header.Get("Authorization") != "Bearer at-2" {
		t.Errorf("after invalidation = %q", seen.Header.Get("Authorization"))
	}

	// Credentials in the request body instead of HTTP Basic.
	body := *cc
	body.ClientAuthInBody = true
	body.Scopes = nil
	p = newProxy(&body, Inject{})
	if w := do(p, "GET", "/api/x", testToken, nil); w.Code != 200 {
		t.Fatalf("body auth status = %d", w.Code)
	}

	// A failing token endpoint fails closed.
	bad := *cc
	bad.ClientSecret = "wrong"
	p = newProxy(&bad, Inject{})
	if w := do(p, "GET", "/api/x", testToken, nil); w.Code != http.StatusBadGateway {
		t.Fatalf("bad credentials status = %d", w.Code)
	}
}

func TestProxyInvalidatesTokenOnUpstream401(t *testing.T) {
	var tokenHits atomic.Int32
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := tokenHits.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"access_token": "at-" + string(rune('0'+n)), "expires_in": 3600})
	}))
	t.Cleanup(idp.Close)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer at-1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		io.WriteString(w, "ok")
	}))
	t.Cleanup(up.Close)
	store, _ := NewMemoryStore(&Config{
		Upstreams: []Upstream{{Name: "api", BaseURL: up.URL, Auth: &UpstreamAuth{Type: UpstreamAuthClientCredentials, TokenURL: idp.URL, ClientID: "c", ClientSecret: "s"}}},
		Policies:  []Policy{{Name: "all", Upstream: "api", Rules: []Rule{{Effect: EffectAllow}}}},
		Clients:   []Client{{Name: "bot", TokenHash: HashToken(testToken), Policies: []string{"all"}}},
	})
	p := NewProxy(store, NewAuditLog(1), ProxyOptions{Logger: quietLogger()})
	if w := do(p, "GET", "/api/x", testToken, nil); w.Code != 401 {
		t.Fatalf("first status = %d", w.Code)
	}
	if w := do(p, "GET", "/api/x", testToken, nil); w.Code != 200 {
		t.Fatalf("second status = %d", w.Code)
	}
}

func TestValidateAuthConfig(t *testing.T) {
	base := func() *Config {
		return &Config{
			Issuers:   []Issuer{{Name: "idp", Issuer: "https://idp", JWKSURL: "https://idp/jwks"}},
			Upstreams: []Upstream{{Name: "api", BaseURL: "https://api"}},
			Clients:   []Client{{Name: "a", Identities: []Identity{{Issuer: "idp", Subject: "x"}}}},
		}
	}
	bad := map[string]func(*Config){
		"issuer without key source": func(c *Config) { c.Issuers[0].JWKSURL = "" },
		"issuer with both sources":  func(c *Config) { c.Issuers[0].HMACSecret = "s" },
		"duplicate iss": func(c *Config) {
			c.Issuers = append(c.Issuers, Issuer{Name: "b", Issuer: "https://idp", HMACSecret: "s"})
		},
		"unknown identity issuer": func(c *Config) { c.Clients[0].Identities[0].Issuer = "nope" },
		"shared identity":         func(c *Config) { c.Clients = append(c.Clients, Client{Name: "b", Identities: c.Clients[0].Identities}) },
		"unknown auth type":       func(c *Config) { c.Upstreams[0].Auth = &UpstreamAuth{Type: "digest"} },
		"basic without password":  func(c *Config) { c.Upstreams[0].Auth = &UpstreamAuth{Type: "basic", Username: "u"} },
		"oauth2 without token url": func(c *Config) {
			c.Upstreams[0].Auth = &UpstreamAuth{Type: "oauth2_client_credentials", ClientID: "c", ClientSecret: "s"}
		},
		"bad vault ref": func(c *Config) { c.Upstreams[0].Inject.Query = map[string]string{"k": "vault:path-without-field"} },
	}
	if err := base().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range bad {
		c := base()
		mutate(c)
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
