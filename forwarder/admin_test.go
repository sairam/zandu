package forwarder

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const adminToken = "admin-token-for-tests"

func newTestAdmin(t *testing.T) (*Admin, *Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "forwarder.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	rt := NewRuntime(NewSecrets(0, slog.New(slog.NewTextHandler(io.Discard, nil))))
	return NewAdmin(store, NewAuditLog(10), rt, adminToken), store, path
}

func call(t *testing.T, h http.Handler, method, path, body string, out any) int {
	t.Helper()
	var rb io.Reader
	if body != "" {
		rb = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, rb)
	r.Header.Set("Authorization", "Bearer "+adminToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if out != nil && w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatalf("%s %s: %v: %s", method, path, err, w.Body)
		}
	}
	return w.Code
}

func TestAdminRequiresToken(t *testing.T) {
	a, _, _ := newTestAdmin(t)
	for _, auth := range []string{"", "Bearer wrong", "Basic " + adminToken} {
		r := httptest.NewRequest("GET", "/api/config", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("auth %q: status = %d", auth, w.Code)
		}
	}
}

func TestAdminServesUI(t *testing.T) {
	a, _, _ := newTestAdmin(t)
	for _, p := range []string{"/", "/app.js", "/app.css", "/logo.svg"} {
		w := httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != http.StatusOK {
			t.Errorf("GET %s: status = %d", p, w.Code)
		}
	}
}

func TestAdminCRUDAndEvaluate(t *testing.T) {
	a, store, path := newTestAdmin(t)

	code := call(t, a, "PUT", "/api/upstreams/api", `{"base_url":"https://api.example.net","inject":{"query":{"key":"plain-secret"}}}`, nil)
	if code != http.StatusNoContent {
		t.Fatalf("put upstream: %d", code)
	}

	var cfg configView
	call(t, a, "GET", "/api/config", "", &cfg)
	if got := cfg.Upstreams[0].Inject.Query["key"]; got != maskedSecret {
		t.Fatalf("literal secret not masked: %q", got)
	}

	// Saving the masked value back keeps the stored secret.
	code = call(t, a, "PUT", "/api/upstreams/api", `{"base_url":"https://api.example.net","description":"d","inject":{"query":{"key":"********"}}}`, nil)
	if code != http.StatusNoContent {
		t.Fatalf("re-put upstream: %d", code)
	}
	if got := store.Config().Upstreams[0].Inject.Query["key"]; got != "plain-secret" {
		t.Fatalf("stored secret = %q", got)
	}

	code = call(t, a, "PUT", "/api/policies/read", `{"upstream":"api","rules":[{"effect":"allow","methods":["GET"],"params":{"command":["get_*"]}}]}`, nil)
	if code != http.StatusNoContent {
		t.Fatalf("put policy: %d", code)
	}

	var invalid map[string]string
	if code := call(t, a, "PUT", "/api/policies/bad", `{"upstream":"missing","rules":[]}`, &invalid); code != http.StatusBadRequest {
		t.Fatalf("invalid policy accepted: %d", code)
	}

	var created map[string]string
	if code := call(t, a, "PUT", "/api/clients/bot", `{"policies":["read"]}`, &created); code != http.StatusOK {
		t.Fatalf("put client: %d", code)
	}
	if !strings.HasPrefix(created["token"], tokenPrefix) {
		t.Fatalf("new client token = %q", created["token"])
	}
	if store.Config().Clients[0].TokenHash != HashToken(created["token"]) {
		t.Fatal("token hash not stored")
	}

	// Updating keeps the token.
	if code := call(t, a, "PUT", "/api/clients/bot", `{"policies":["read"],"description":"x"}`, &created); code != http.StatusNoContent {
		t.Fatalf("update client: %d", code)
	}

	var ev evaluateResponse
	call(t, a, "POST", "/api/evaluate", `{"client":"bot","url":"/api/v1?command=get_dns&key=x"}`, &ev)
	if !ev.Decision.Allowed || ev.Params.Has("key") {
		t.Fatalf("evaluate = %+v", ev)
	}
	call(t, a, "POST", "/api/evaluate", `{"client":"bot","url":"/api/v1?command=delete"}`, &ev)
	if ev.Decision.Allowed {
		t.Fatalf("evaluate delete = %+v", ev)
	}

	var rotated map[string]string
	call(t, a, "POST", "/api/clients/bot/token", "", &rotated)
	if store.Config().Clients[0].TokenHash != HashToken(rotated["token"]) {
		t.Fatal("rotated token not stored")
	}

	// Referential integrity: an upstream in use cannot be deleted.
	if code := call(t, a, "DELETE", "/api/upstreams/api", "", nil); code != http.StatusBadRequest {
		t.Fatalf("delete referenced upstream: %d", code)
	}
	if code := call(t, a, "DELETE", "/api/clients/nope", "", nil); code != http.StatusNotFound {
		t.Fatalf("delete missing client: %d", code)
	}

	// Changes are persisted and survive a reload.
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"name": "bot"`) {
		t.Fatalf("config not persisted: %s", b)
	}
	if err := store.Reload(); err != nil {
		t.Fatal(err)
	}
}

func TestAdminApplyDynadotPreset(t *testing.T) {
	a, store, _ := newTestAdmin(t)

	var res map[string][]string
	if code := call(t, a, "POST", "/api/presets/dynadot", "", &res); code != http.StatusOK {
		t.Fatalf("apply preset: %d", code)
	}

	// Secrets are resolved on use; the check endpoint reports a missing one.
	var check map[string]any
	call(t, a, "POST", "/api/upstreams/dynadot/check", "", &check)
	if check["ok"] != false || !strings.Contains(check["error"].(string), "DYNADOT_API_KEY") {
		t.Fatalf("check without env = %v", check)
	}
	t.Setenv("DYNADOT_API_KEY", "k")
	call(t, a, "POST", "/api/upstreams/dynadot/check", "", &check)
	if check["ok"] != true {
		t.Fatalf("check with env = %v", check)
	}
	if len(res["added"]) != 3 {
		t.Fatalf("added = %v", res["added"])
	}
	call(t, a, "POST", "/api/presets/dynadot", "", &res)
	if len(res["added"]) != 0 || len(res["skipped"]) != 3 {
		t.Fatalf("second apply = %v", res)
	}
	call(t, a, "PUT", "/api/clients/dns", `{"policies":["dynadot-dns-example-com"]}`, nil)
	call(t, a, "PUT", "/api/clients/ro", `{"policies":["dynadot-read-only"]}`, nil)

	cases := []struct {
		client, url string
		allowed     bool
	}{
		{"dns", "/dynadot/api3.json?command=set_dns2&domain=example.com&main_record_type0=a&main_record0=1.2.3.4", true},
		{"dns", "/dynadot/api3.xml?command=get_dns&domain=example.com", true},
		{"dns", "/dynadot/api3.json?command=set_dns2&domain=other.com", false},
		{"dns", "/dynadot/api3.json?command=delete&domain=example.com", false},
		{"ro", "/dynadot/api3.json?command=search&domain0=a.com&domain1=b.net", true},
		{"ro", "/dynadot/api3.json?command=list_domain", true},
		{"ro", "/dynadot/api3.json?command=register&domain=a.com&duration=1", false},
		{"ro", "/dynadot/api3.json?command=push&domain=a.com", false},
	}
	for _, c := range cases {
		var ev evaluateResponse
		call(t, a, "POST", "/api/evaluate", `{"client":"`+c.client+`","url":"`+c.url+`"}`, &ev)
		if ev.Decision.Allowed != c.allowed {
			t.Errorf("%s %s: allowed = %v, want %v (%s)", c.client, c.url, ev.Decision.Allowed, c.allowed, ev.Decision.Reason)
		}
	}

	// The proxy picks up admin changes immediately.
	up, seen := fakeUpstream(t)
	err := store.Update(func(c *Config) error {
		c.Upstreams[0].BaseURL = up.URL
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var tok map[string]string
	call(t, a, "POST", "/api/clients/dns/token", "", &tok)
	p := NewProxy(store, NewAuditLog(1), ProxyOptions{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	w := do(p, "GET", "/dynadot/api3.json?command=get_dns&domain=example.com", tok["token"], nil)
	if w.Code != http.StatusOK || seen.Query.Get("key") != "k" {
		t.Fatalf("proxy status = %d, upstream query = %v", w.Code, seen.Query)
	}
}

func TestAdminApplyNamecheapPreset(t *testing.T) {
	a, _, _ := newTestAdmin(t)
	for _, k := range []string{"NAMECHEAP_API_USER", "NAMECHEAP_API_KEY", "NAMECHEAP_USERNAME", "NAMECHEAP_CLIENT_IP"} {
		t.Setenv(k, "v")
	}
	var res map[string][]string
	if code := call(t, a, "POST", "/api/presets/namecheap", "", &res); code != http.StatusOK || len(res["added"]) != 3 {
		t.Fatalf("apply preset: %d %v", code, res)
	}
	call(t, a, "PUT", "/api/clients/dns", `{"policies":["namecheap-dns-example-com"]}`, nil)
	call(t, a, "PUT", "/api/clients/ro", `{"policies":["namecheap-read-only"]}`, nil)

	const base = "/namecheap/xml.response?"
	cases := []struct {
		client, method, url, body string
		allowed                   bool
	}{
		{"dns", "GET", base + "Command=namecheap.domains.dns.getHosts&SLD=example&TLD=com", "", true},
		{"dns", "GET", base + "command=NAMECHEAP.DOMAINS.DNS.GETHOSTS&sld=Example&tld=COM", "", true},
		{"dns", "POST", base, "Command=namecheap.domains.dns.setHosts&SLD=example&TLD=com&HostName1=@&RecordType1=A&Address1=1.2.3.4", true},
		{"dns", "GET", base + "Command=namecheap.domains.getInfo&DomainName=example.com", "", true},
		{"dns", "GET", base + "Command=namecheap.domains.dns.setHosts&SLD=other&TLD=com", "", false},
		{"dns", "GET", base + "Command=namecheap.domains.getInfo&DomainName=other.com", "", false},
		// A forbidden command hidden in the body alongside an allowed one.
		{"dns", "POST", base + "Command=namecheap.domains.dns.getHosts&SLD=example&TLD=com", "Command=namecheap.domains.transfer.create", false},
		// Acting on another account under a reseller API user.
		{"dns", "GET", base + "Command=namecheap.domains.dns.getHosts&SLD=example&TLD=com&UserName=someone-else", "", true},
		{"ro", "GET", base + "Command=namecheap.domains.getList", "", true},
		{"ro", "GET", base + "Command=namecheap.domains.create&DomainName=a.com", "", false},
		{"ro", "GET", base + "Command=namecheap.domains.dns.setHosts&SLD=example&TLD=com", "", false},
	}
	for _, c := range cases {
		var ev evaluateResponse
		body, _ := json.Marshal(evaluateRequest{Client: c.client, Method: c.method, URL: c.url, Body: c.body})
		call(t, a, "POST", "/api/evaluate", string(body), &ev)
		if ev.Decision.Allowed != c.allowed {
			t.Errorf("%s %s %s: allowed = %v, want %v (%s)", c.client, c.method, c.url, ev.Decision.Allowed, c.allowed, ev.Decision.Reason)
		}
		// Injected credentials are never taken from the client.
		for k := range ev.Params {
			if strings.EqualFold(k, "UserName") || strings.EqualFold(k, "ApiKey") {
				t.Errorf("%s: client-supplied %s reached evaluation", c.url, k)
			}
		}
	}
}

func TestStoreRejectsInvalidFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(path, []byte(`{"clients":[{"name":"x","policies":["missing"]}]}`), 0o600)
	if _, err := OpenStore(path); err == nil || !strings.Contains(err.Error(), "unknown policy") {
		t.Fatalf("err = %v", err)
	}
}

func TestStoreRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(path, []byte(`{"upstreams":[],"policies":[{"name":"p","upstream":"x","rules":[{"efect":"allow"}]}]}`), 0o600)
	if _, err := OpenStore(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("err = %v", err)
	}
}

func TestStoreUpdateIsAtomic(t *testing.T) {
	store, err := NewMemoryStore(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	err = store.Update(func(c *Config) error {
		c.Upstreams = append(c.Upstreams, Upstream{Name: "Bad Name", BaseURL: "https://x"})
		return nil
	})
	if err == nil {
		t.Fatal("invalid update accepted")
	}
	if len(store.Config().Upstreams) != 0 {
		t.Fatal("invalid update was applied")
	}
}

func TestAuditLogRing(t *testing.T) {
	a := NewAuditLog(3)
	for i := 1; i <= 5; i++ {
		a.Add(AuditEntry{Status: i})
	}
	got := a.Recent(0)
	if len(got) != 3 || got[0].Status != 5 || got[2].Status != 3 {
		t.Fatalf("recent = %+v", got)
	}
	if got := a.Recent(1); len(got) != 1 || got[0].Status != 5 {
		t.Fatalf("recent(1) = %+v", got)
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	b, err := os.ReadFile("../examples/forwarder.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
