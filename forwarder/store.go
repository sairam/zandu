package forwarder

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	tokenPrefix     = "zfw_"
	tokenHashPrefix = "sha256:"
)

// NewToken returns a new random client token and its stored hash.
func NewToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	token = tokenPrefix + base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken returns the value stored in Client.TokenHash for token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return tokenHashPrefix + hex.EncodeToString(sum[:])
}

type compiledUpstream struct {
	Upstream
	target  *url.URL
	query   map[string]string
	headers map[string]string
	timeout time.Duration
}

type compiledClient struct {
	name       string
	disabled   bool
	allowedIPs []netip.Prefix
	policies   []*compiledPolicy
}

// snapshot is an immutable, compiled view of a Config.
type snapshot struct {
	cfg       *Config
	upstreams map[string]*compiledUpstream
	clients   map[string]*compiledClient // keyed by name
	byToken   map[string]*compiledClient // keyed by token hash
}

func compile(cfg *Config) (*snapshot, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	s := &snapshot{
		cfg:       cfg,
		upstreams: map[string]*compiledUpstream{},
		clients:   map[string]*compiledClient{},
		byToken:   map[string]*compiledClient{},
	}
	for _, u := range cfg.Upstreams {
		target, _ := parseBaseURL(u.BaseURL)
		cu := &compiledUpstream{
			Upstream: u,
			target:   target,
			query:    map[string]string{},
			headers:  map[string]string{},
			timeout:  30 * time.Second,
		}
		if u.TimeoutSeconds > 0 {
			cu.timeout = time.Duration(u.TimeoutSeconds) * time.Second
		}
		for k, v := range u.Inject.Query {
			rv, err := resolveSecret(v)
			if err != nil {
				return nil, fmt.Errorf("upstream %q: query %q: %w", u.Name, k, err)
			}
			cu.query[k] = rv
		}
		for k, v := range u.Inject.Headers {
			rv, err := resolveSecret(v)
			if err != nil {
				return nil, fmt.Errorf("upstream %q: header %q: %w", u.Name, k, err)
			}
			cu.headers[k] = rv
		}
		s.upstreams[u.Name] = cu
	}
	policies := map[string]*compiledPolicy{}
	for _, p := range cfg.Policies {
		cp := compilePolicy(p)
		policies[p.Name] = &cp
	}
	for _, c := range cfg.Clients {
		cc := &compiledClient{name: c.Name, disabled: c.Disabled}
		for _, ip := range c.AllowedIPs {
			p, _ := parsePrefix(ip)
			cc.allowedIPs = append(cc.allowedIPs, p)
		}
		for _, pn := range c.Policies {
			cc.policies = append(cc.policies, policies[pn])
		}
		s.clients[c.Name] = cc
		if c.TokenHash != "" {
			s.byToken[c.TokenHash] = cc
		}
	}
	return s, nil
}

func (c *compiledClient) ipAllowed(ip netip.Addr) bool {
	if len(c.allowedIPs) == 0 {
		return true
	}
	ip = ip.Unmap()
	for _, p := range c.allowedIPs {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Store holds the active configuration and persists changes to a JSON file.
type Store struct {
	path string
	mu   sync.Mutex // serializes writers
	cur  atomic.Pointer[snapshot]
}

// OpenStore loads the configuration at path, creating an empty one if the
// file does not exist.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := writeFileAtomic(path, &Config{}); err != nil {
			return nil, err
		}
	}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// NewMemoryStore returns a store that is not backed by a file.
func NewMemoryStore(cfg *Config) (*Store, error) {
	snap, err := compile(cfg.clone())
	if err != nil {
		return nil, err
	}
	s := &Store{}
	s.cur.Store(snap)
	return s, nil
}

// Reload re-reads the configuration file.
func (s *Store) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return nil
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	cfg := &Config{}
	if err := json.Unmarshal(b, cfg); err != nil {
		return fmt.Errorf("%s: %w", s.path, err)
	}
	snap, err := compile(cfg)
	if err != nil {
		return fmt.Errorf("%s: %w", s.path, err)
	}
	s.cur.Store(snap)
	return nil
}

// Config returns a copy of the active configuration.
func (s *Store) Config() *Config {
	return s.cur.Load().cfg.clone()
}

func (s *Store) snapshot() *snapshot {
	return s.cur.Load()
}

// Update applies fn to a copy of the configuration, then validates, persists
// and activates the result. Nothing changes if fn or validation fails.
func (s *Store) Update(fn func(*Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg := s.cur.Load().cfg.clone()
	if err := fn(cfg); err != nil {
		return err
	}
	snap, err := compile(cfg)
	if err != nil {
		return err
	}
	if s.path != "" {
		if err := writeFileAtomic(s.path, cfg); err != nil {
			return err
		}
	}
	s.cur.Store(snap)
	return nil
}

func writeFileAtomic(path string, cfg *Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".forwarder-*.json")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
