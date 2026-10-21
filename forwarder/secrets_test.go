package forwarder

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestSecretsResolve(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "key.txt")
	os.WriteFile(plain, []byte("  from-file\n"), 0o600)
	shared := filepath.Join(dir, "secrets.json")
	os.WriteFile(shared, []byte(`{"dynadot":{"key":"dk","port":8443},"flat":"f"}`), 0o600)
	t.Setenv("ZANDU_TEST_SECRET", "from-env")

	s := NewSecrets(time.Minute, quietLogger())
	cases := []struct {
		in, want, err string
	}{
		{in: "literal", want: "literal"},
		{in: "user:pass", want: "user:pass"},
		{in: "env:ZANDU_TEST_SECRET", want: "from-env"},
		{in: "env:ZANDU_TEST_MISSING", err: "not set"},
		{in: "file:" + plain, want: "from-file"},
		{in: "file:" + shared + "#dynadot.key", want: "dk"},
		{in: "file:" + shared + "#dynadot.port", want: "8443"},
		{in: "file:" + shared + "#flat", want: "f"},
		{in: "file:" + shared + "#dynadot", err: "not a scalar"},
		{in: "file:" + shared + "#nope", err: "not found"},
		{in: "vault:secret/data/x#y", err: "not configured"},
	}
	for _, c := range cases {
		got, err := s.Resolve(context.Background(), c.in)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("%s: err = %v, want %q", c.in, err, c.err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

type countingProvider struct {
	calls atomic.Int32
	value atomic.Value
	fail  atomic.Bool
}

func (p *countingProvider) Resolve(context.Context, string) (string, error) {
	p.calls.Add(1)
	if p.fail.Load() {
		return "", errors.New("store unavailable")
	}
	return p.value.Load().(string), nil
}

func TestSecretsCacheAndStaleFallback(t *testing.T) {
	p := &countingProvider{}
	p.value.Store("v1")
	s := NewSecrets(time.Hour, quietLogger())
	s.Register("vault", p)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if v, _ := s.Resolve(ctx, "vault:a#b"); v != "v1" {
			t.Fatalf("got %q", v)
		}
	}
	if p.calls.Load() != 1 {
		t.Fatalf("provider called %d times, want 1", p.calls.Load())
	}

	// Expire the entry; a failed refresh serves the last good value.
	s.ttl = 0
	p.fail.Store(true)
	if v, err := s.Resolve(ctx, "vault:a#b"); err != nil || v != "v1" {
		t.Fatalf("stale fallback = %q, %v", v, err)
	}
	// A successful refresh picks up the rotated value.
	p.fail.Store(false)
	p.value.Store("v2")
	if v, _ := s.Resolve(ctx, "vault:a#b"); v != "v2" {
		t.Fatalf("rotated = %q", v)
	}
	// Nothing cached and the store is down: an error.
	p.fail.Store(true)
	if _, err := s.Resolve(ctx, "vault:other#b"); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateSecretRef(t *testing.T) {
	for _, v := range []string{"env:", "file:", "file:#k", "vault:path", "vault:#f"} {
		if validateSecretRef(v) == nil {
			t.Errorf("%q accepted", v)
		}
	}
	for _, v := range []string{"plain", "env:X", "file:/x", "file:/x#a.b", "vault:secret/data/x#f"} {
		if err := validateSecretRef(v); err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
}

// fakeVault serves KV v2 at secret/, KV v1 at kv/ and an AppRole login.
// Tokens are valid until revoked by setting validToken.
func fakeVault(t *testing.T) (*httptest.Server, *atomic.Value, *atomic.Int32) {
	t.Helper()
	valid := &atomic.Value{}
	valid.Store("tok-1")
	logins := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Namespace") != "team" {
			http.Error(w, "namespace", http.StatusBadRequest)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/auth/approle/login":
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			if in["role_id"] != "role" || in["secret_id"] != "sid" {
				http.Error(w, "denied", http.StatusForbidden)
				return
			}
			logins.Add(1)
			io.WriteString(w, `{"auth":{"client_token":"`+valid.Load().(string)+`"}}`)
			return
		case r.Header.Get("X-Vault-Token") != valid.Load().(string):
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		case r.URL.Path == "/v1/secret/data/dynadot":
			io.WriteString(w, `{"data":{"data":{"api_key":"kv2-key"},"metadata":{"version":3}}}`)
		case r.URL.Path == "/v1/kv/namecheap":
			io.WriteString(w, `{"data":{"api_key":"kv1-key"}}`)
		default:
			http.Error(w, "{}", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, valid, logins
}

func TestVaultProvider(t *testing.T) {
	srv, valid, logins := fakeVault(t)
	ctx := context.Background()

	v := &VaultProvider{Addr: srv.URL, Namespace: "team", Token: "tok-1"}
	if got, err := v.Resolve(ctx, "secret/data/dynadot#api_key"); err != nil || got != "kv2-key" {
		t.Fatalf("kv2 = %q, %v", got, err)
	}
	if got, err := v.Resolve(ctx, "kv/namecheap#api_key"); err != nil || got != "kv1-key" {
		t.Fatalf("kv1 = %q, %v", got, err)
	}
	if _, err := v.Resolve(ctx, "secret/data/missing#x"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing = %v", err)
	}
	if _, err := v.Resolve(ctx, "secret/data/dynadot#nope"); err == nil {
		t.Fatal("missing field accepted")
	}

	// AppRole logs in lazily and again after the token is revoked.
	ar := &VaultProvider{Addr: srv.URL, Namespace: "team", RoleID: "role", SecretID: "sid"}
	if got, err := ar.Resolve(ctx, "secret/data/dynadot#api_key"); err != nil || got != "kv2-key" {
		t.Fatalf("approle = %q, %v", got, err)
	}
	valid.Store("tok-2")
	if got, err := ar.Resolve(ctx, "secret/data/dynadot#api_key"); err != nil || got != "kv2-key" {
		t.Fatalf("approle after revoke = %q, %v", got, err)
	}
	if logins.Load() != 2 {
		t.Fatalf("logins = %d, want 2", logins.Load())
	}

	// A token file is re-read after a denial.
	tf := filepath.Join(t.TempDir(), "token")
	os.WriteFile(tf, []byte("stale"), 0o600)
	fv := &VaultProvider{Addr: srv.URL, Namespace: "team", TokenFile: tf}
	if _, err := fv.Resolve(ctx, "kv/namecheap#api_key"); err == nil {
		t.Fatal("stale token accepted")
	}
	os.WriteFile(tf, []byte("tok-2\n"), 0o600)
	if got, err := fv.Resolve(ctx, "kv/namecheap#api_key"); err != nil || got != "kv1-key" {
		t.Fatalf("token file = %q, %v", got, err)
	}
}

func TestProxyUsesVaultSecretsAndRotation(t *testing.T) {
	vault, _, _ := fakeVault(t)
	up, seen := fakeUpstream(t)
	secrets := NewSecrets(0, quietLogger())
	secrets.Register("vault", &VaultProvider{Addr: vault.URL, Namespace: "team", Token: "tok-1"})
	store, err := NewMemoryStore(&Config{
		Upstreams: []Upstream{{Name: "dynadot", BaseURL: up.URL, Inject: Inject{Query: map[string]string{"key": "vault:secret/data/dynadot#api_key"}}}},
		Policies:  []Policy{{Name: "all", Upstream: "dynadot", Rules: []Rule{{Effect: EffectAllow}}}},
		Clients:   []Client{{Name: "bot", TokenHash: HashToken(testToken), Policies: []string{"all"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxy(store, NewAuditLog(1), ProxyOptions{Runtime: NewRuntime(secrets), Logger: quietLogger()})
	if w := do(p, "GET", "/dynadot/api3.json", testToken, nil); w.Code != 200 || seen.Query.Get("key") != "kv2-key" {
		t.Fatalf("status = %d, key = %q", w.Code, seen.Query.Get("key"))
	}

	// An unreachable secret store with nothing cached fails closed.
	vault.Close()
	if w := do(p, "GET", "/dynadot/other", testToken, nil); w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d", w.Code)
	}
}
