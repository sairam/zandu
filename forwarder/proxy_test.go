package forwarder

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

type seenRequest struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   string
}

// fakeUpstream records the last request it received.
func fakeUpstream(t *testing.T) (*httptest.Server, *seenRequest) {
	t.Helper()
	seen := &seenRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		*seen = seenRequest{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone(), Body: string(b)}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

const testToken = "zfw_test-token"

func newTestProxy(t *testing.T, upstreamURL string, opts ProxyOptions) (*Proxy, *AuditLog) {
	t.Helper()
	t.Setenv("TEST_DYNADOT_KEY", "secret-key")
	cfg := &Config{
		Upstreams: []Upstream{{
			Name:    "dynadot",
			BaseURL: upstreamURL + "/base",
			Inject: Inject{
				Query:   map[string]string{"key": "env:TEST_DYNADOT_KEY"},
				Headers: map[string]string{"X-Api-Secret": "literal-secret"},
			},
		}},
		Policies: []Policy{{
			Name:     "dns",
			Upstream: "dynadot",
			Rules: []Rule{{
				Effect:  EffectAllow,
				Methods: []string{"GET", "POST"},
				Path:    "/api3.json",
				Params: map[string][]string{
					"command": {"get_dns", "set_dns2"},
					"domain":  {"example.com"},
				},
			}},
		}},
		Clients: []Client{
			{Name: "bot", TokenHash: HashToken(testToken), Policies: []string{"dns"}},
			{Name: "off", TokenHash: HashToken("zfw_off"), Policies: []string{"dns"}, Disabled: true},
			{Name: "office", TokenHash: HashToken("zfw_office"), Policies: []string{"dns"}, AllowedIPs: []string{"10.0.0.0/8"}},
		},
	}
	store, err := NewMemoryStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	audit := NewAuditLog(10)
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return NewProxy(store, audit, opts), audit
}

func do(p http.Handler, method, target, token string, body io.Reader, mutate ...func(*http.Request)) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, body)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for _, m := range mutate {
		m(r)
	}
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

func TestProxyForwardsAllowedRequest(t *testing.T) {
	up, seen := fakeUpstream(t)
	p, audit := newTestProxy(t, up.URL, ProxyOptions{})

	w := do(p, "GET", "/dynadot/api3.json?command=get_dns&domain=example.com&key=client-key", testToken, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	if w.Body.String() != `{"ok":true}` {
		t.Fatalf("body = %s", w.Body)
	}
	if seen.Path != "/base/api3.json" {
		t.Errorf("upstream path = %q", seen.Path)
	}
	if got := seen.Query["key"]; len(got) != 1 || got[0] != "secret-key" {
		t.Errorf("upstream key = %v, want injected secret only", got)
	}
	if seen.Query.Get("command") != "get_dns" || seen.Query.Get("domain") != "example.com" {
		t.Errorf("upstream query = %v", seen.Query)
	}
	if seen.Header.Get("Authorization") != "" {
		t.Error("client Authorization header was forwarded")
	}
	if seen.Header.Get("X-Api-Secret") != "literal-secret" {
		t.Error("injected header missing")
	}
	e := audit.Recent(1)[0]
	if !e.Allowed || e.Client != "bot" || e.Status != 200 || strings.Contains(e.Query, "secret") {
		t.Errorf("audit entry = %+v", e)
	}
}

func TestProxyStripsCaseVariantsOfInjectedParams(t *testing.T) {
	up, seen := fakeUpstream(t)
	p, _ := newTestProxy(t, up.URL, ProxyOptions{})
	w := do(p, "GET", "/dynadot/api3.json?command=get_dns&domain=example.com&KEY=other", testToken, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	for k := range seen.Query {
		if strings.EqualFold(k, "key") && k != "key" {
			t.Fatalf("client-supplied %q was forwarded", k)
		}
	}
}

func TestProxyDenials(t *testing.T) {
	up, _ := fakeUpstream(t)
	p, _ := newTestProxy(t, up.URL, ProxyOptions{})
	cases := []struct {
		name   string
		method string
		target string
		token  string
		body   string
		ctype  string
		want   int
	}{
		{"unknown upstream", "GET", "/nope/x", testToken, "", "", 404},
		{"missing token", "GET", "/dynadot/api3.json?command=get_dns&domain=example.com", "", "", "", 401},
		{"bad token", "GET", "/dynadot/api3.json?command=get_dns&domain=example.com", "zfw_wrong", "", "", 401},
		{"disabled client", "GET", "/dynadot/api3.json?command=get_dns&domain=example.com", "zfw_off", "", "", 403},
		{"ip not allowed", "GET", "/dynadot/api3.json?command=get_dns&domain=example.com", "zfw_office", "", "", 403},
		{"policy deny", "GET", "/dynadot/api3.json?command=delete&domain=example.com", testToken, "", "", 403},
		{"path traversal", "GET", "/dynadot/x/../api3.xml?command=get_dns&domain=example.com", testToken, "", "", 403},
		{"semicolon query", "GET", "/dynadot/api3.json?command=get_dns;domain=example.com", testToken, "", "", 400},
		{"forbidden command in form body", "POST", "/dynadot/api3.json?command=get_dns&domain=example.com", testToken, "command=delete", "application/x-www-form-urlencoded", 403},
		{"malformed content type", "POST", "/dynadot/api3.json?command=get_dns&domain=example.com", testToken, "command=delete", "application/x-www-form-urlencoded; =", 415},
		{"multipart body", "POST", "/dynadot/api3.json?command=get_dns&domain=example.com", testToken, "x", "multipart/form-data; boundary=x", 415},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var body io.Reader
			if c.body != "" {
				body = strings.NewReader(c.body)
			}
			w := do(p, c.method, c.target, c.token, body, func(r *http.Request) {
				if c.ctype != "" {
					r.Header.Set("Content-Type", c.ctype)
				}
			})
			if w.Code != c.want {
				t.Fatalf("status = %d, want %d, body = %s", w.Code, c.want, w.Body)
			}
		})
	}
}

func TestProxyRejectsDuplicateContentType(t *testing.T) {
	up, _ := fakeUpstream(t)
	p, _ := newTestProxy(t, up.URL, ProxyOptions{})
	w := do(p, "POST", "/dynadot/api3.json?command=get_dns&domain=example.com", testToken, strings.NewReader("command=delete"), func(r *http.Request) {
		r.Header.Add("Content-Type", "text/plain")
		r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	})
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestProxyForwardsFormBody(t *testing.T) {
	up, seen := fakeUpstream(t)
	p, _ := newTestProxy(t, up.URL, ProxyOptions{})
	w := do(p, "POST", "/dynadot/api3.json", testToken,
		strings.NewReader("command=set_dns2&domain=example.com&key=client-key&main_record0=1.2.3.4"),
		func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") })
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body)
	}
	form, _ := url.ParseQuery(seen.Body)
	if form.Get("main_record0") != "1.2.3.4" || form.Has("key") {
		t.Errorf("upstream body = %q", seen.Body)
	}
	if seen.Query.Get("key") != "secret-key" {
		t.Errorf("upstream query = %v", seen.Query)
	}
}

func TestProxyTrustedProxies(t *testing.T) {
	up, _ := fakeUpstream(t)
	lb := netip.MustParsePrefix("192.0.2.0/24")
	p, _ := newTestProxy(t, up.URL, ProxyOptions{TrustedProxies: []netip.Prefix{lb}})
	target := "/dynadot/api3.json?command=get_dns&domain=example.com"
	via := func(peer, xff string) func(*http.Request) {
		return func(r *http.Request) {
			r.RemoteAddr = peer + ":1234"
			r.Header.Set("X-Forwarded-For", xff)
		}
	}
	if w := do(p, "GET", target, "zfw_office", nil, via("192.0.2.1", "10.1.2.3")); w.Code != 200 {
		t.Errorf("trusted proxy: status = %d", w.Code)
	}
	if w := do(p, "GET", target, "zfw_office", nil, via("198.51.100.1", "10.1.2.3")); w.Code != 403 {
		t.Errorf("untrusted peer spoofing XFF: status = %d", w.Code)
	}
	if w := do(p, "GET", target, "zfw_office", nil, via("192.0.2.1", "10.1.2.3, 203.0.113.9")); w.Code != 403 {
		t.Errorf("rightmost untrusted hop must be used: status = %d", w.Code)
	}
}

func TestProxyUpstreamError(t *testing.T) {
	up, _ := fakeUpstream(t)
	p, audit := newTestProxy(t, up.URL, ProxyOptions{})
	up.Close()
	w := do(p, "GET", "/dynadot/api3.json?command=get_dns&domain=example.com", testToken, nil)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d", w.Code)
	}
	var e map[string]string
	json.Unmarshal(w.Body.Bytes(), &e)
	if e["error"] != "upstream_error" {
		t.Errorf("body = %s", w.Body)
	}
	if got := audit.Recent(1)[0].Status; got != http.StatusBadGateway {
		t.Errorf("audit status = %d", got)
	}
}

func TestProxyHealth(t *testing.T) {
	p, _ := newTestProxy(t, "http://127.0.0.1:1", ProxyOptions{})
	if w := do(p, "GET", HealthPath, "", nil); w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
}
