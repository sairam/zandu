package forwarder

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Secret references are configuration values of the form "<scheme>:<ref>".
// Any other value is used literally.
//
//	env:NAME                      environment variable
//	file:/path                    whole file, trimmed
//	file:/path#a.b                string at a dotted key in a JSON file
//	vault:secret/data/app#field   field of a HashiCorp Vault secret
var secretSchemes = []string{"env", "file", "vault"}

// SecretProvider resolves the reference part of a secret for one scheme.
type SecretProvider interface {
	Resolve(ctx context.Context, ref string) (string, error)
}

// Secrets resolves secret references through registered providers and caches
// the results. When a refresh fails, the last good value is served so that a
// brief outage of a secret store does not interrupt traffic.
type Secrets struct {
	ttl       time.Duration
	providers map[string]SecretProvider
	logger    *slog.Logger

	mu    sync.Mutex
	cache map[string]cachedSecret
}

type cachedSecret struct {
	value   string
	fetched time.Time
}

// NewSecrets returns a resolver with the env and file providers registered.
// ttl bounds how long a resolved value is reused; zero disables caching.
func NewSecrets(ttl time.Duration, logger *slog.Logger) *Secrets {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Secrets{
		ttl:       ttl,
		providers: map[string]SecretProvider{},
		logger:    logger,
		cache:     map[string]cachedSecret{},
	}
	s.Register("env", envProvider{})
	s.Register("file", fileProvider{})
	return s
}

// Register sets the provider for scheme, which must be one of the supported
// secret schemes.
func (s *Secrets) Register(scheme string, p SecretProvider) {
	s.providers[scheme] = p
}

// Resolve returns the value of v, resolving it if it is a secret reference.
func (s *Secrets) Resolve(ctx context.Context, v string) (string, error) {
	scheme, ref, ok := splitSecretRef(v)
	if !ok {
		return v, nil
	}
	p := s.providers[scheme]
	if p == nil {
		return "", fmt.Errorf("%s: secret source is not configured", scheme)
	}

	s.mu.Lock()
	c, cached := s.cache[v]
	s.mu.Unlock()
	if cached && time.Since(c.fetched) < s.ttl {
		return c.value, nil
	}

	val, err := p.Resolve(ctx, ref)
	if err == nil && val == "" {
		err = fmt.Errorf("value is empty")
	}
	if err != nil {
		err = fmt.Errorf("%s: %w", redactRef(v), err)
		if cached {
			s.logger.Warn("secret refresh failed; using last known value", "error", err)
			return c.value, nil
		}
		return "", err
	}
	if s.ttl > 0 {
		s.mu.Lock()
		s.cache[v] = cachedSecret{value: val, fetched: time.Now()}
		s.mu.Unlock()
	}
	return val, nil
}

// splitSecretRef splits a value into scheme and reference if it uses one of
// the supported secret schemes.
func splitSecretRef(v string) (scheme, ref string, ok bool) {
	scheme, ref, found := strings.Cut(v, ":")
	if !found {
		return "", "", false
	}
	for _, s := range secretSchemes {
		if scheme == s {
			return scheme, ref, true
		}
	}
	return "", "", false
}

// isSecretRef reports whether v refers to a secret instead of embedding it.
func isSecretRef(v string) bool {
	_, _, ok := splitSecretRef(v)
	return ok
}

// validateSecretRef checks the syntax of a secret reference.
func validateSecretRef(v string) error {
	scheme, ref, ok := splitSecretRef(v)
	if !ok {
		return nil
	}
	switch scheme {
	case "env":
		if ref == "" {
			return fmt.Errorf("env: missing variable name")
		}
	case "file":
		if p, _, _ := strings.Cut(ref, "#"); p == "" {
			return fmt.Errorf("file: missing path")
		}
	case "vault":
		p, field, _ := strings.Cut(ref, "#")
		if p == "" || field == "" {
			return fmt.Errorf("vault: expected vault:<path>#<field>")
		}
	}
	return nil
}

// redactRef returns a reference suitable for error messages.
func redactRef(v string) string {
	if isSecretRef(v) {
		return v
	}
	return "literal value"
}

type envProvider struct{}

func (envProvider) Resolve(_ context.Context, name string) (string, error) {
	v, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("environment variable is not set")
	}
	return v, nil
}

type fileProvider struct{}

// Resolve reads "path" or "path#dotted.key". With a key, the file must be a
// JSON object; this lets one secrets file be shared with other tooling.
func (fileProvider) Resolve(_ context.Context, ref string) (string, error) {
	path, key, _ := strings.Cut(ref, "#")
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if key == "" {
		return strings.TrimSpace(string(b)), nil
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		return "", fmt.Errorf("parse JSON: %w", err)
	}
	return lookupKey(doc, key)
}

// lookupKey walks a dotted key through nested JSON objects.
func lookupKey(doc any, key string) (string, error) {
	cur := doc
	for _, part := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", fmt.Errorf("key %q not found", key)
		}
		if cur, ok = m[part]; !ok {
			return "", fmt.Errorf("key %q not found", key)
		}
	}
	switch v := cur.(type) {
	case string:
		return v, nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(v), nil
	default:
		return "", fmt.Errorf("key %q is not a scalar value", key)
	}
}
