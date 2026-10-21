// Package forwarder implements a permission-aware API forwarder.
//
// The forwarder sits between internal clients and third-party APIs that
// offer coarse-grained (or IP-only) authorization. It holds the upstream
// credentials itself, issues scoped tokens to clients, and forwards a request
// only when one of the client's policies allows it.
package forwarder

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Config is the persisted forwarder configuration.
type Config struct {
	Upstreams []Upstream `json:"upstreams"`
	Policies  []Policy   `json:"policies"`
	Clients   []Client   `json:"clients"`
}

// Upstream is a third-party API the forwarder can reach.
type Upstream struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// BaseURL is the scheme, host and optional path prefix of the API,
	// e.g. "https://api.dynadot.com".
	BaseURL string `json:"base_url"`
	// Inject lists credentials added to every forwarded request. Values may
	// be literals, "env:NAME" or "file:/path".
	Inject Inject `json:"inject,omitempty"`
	// TimeoutSeconds bounds each upstream request. Zero means 30 seconds.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// Inject holds credentials the forwarder adds to upstream requests.
// Client-supplied values for the same names are always replaced.
type Inject struct {
	Query   map[string]string `json:"query,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// Policy is a named, reusable set of rules for one upstream.
type Policy struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Upstream    string `json:"upstream"`
	Rules       []Rule `json:"rules"`
}

// Rule matches requests by method, path and parameters.
//
// All matching is case-insensitive. A request matches a rule when:
//   - its method is in Methods (or Methods is empty),
//   - its path matches the Path glob (or Path is empty), and
//   - every Params constraint is satisfied.
//
// Params maps a parameter name (or a glob such as "domain*") to value globs.
// For allow rules, every value of every parameter whose name matches must
// match one of the globs, and a name without wildcards must be present. For
// deny rules, a single matching value is enough. Parameters are read from the
// query string and from application/x-www-form-urlencoded bodies.
type Rule struct {
	Effect      string              `json:"effect"`
	Description string              `json:"description,omitempty"`
	Methods     []string            `json:"methods,omitempty"`
	Path        string              `json:"path,omitempty"`
	Params      map[string][]string `json:"params,omitempty"`
}

// Client is a caller of the forwarder.
type Client struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	TokenHash   string   `json:"token_hash,omitempty"`
	Policies    []string `json:"policies"`
	// AllowedIPs restricts the source addresses (IPs or CIDRs) the client
	// may call from. Empty means any address.
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	Disabled   bool     `json:"disabled,omitempty"`
}

const (
	EffectAllow = "allow"
	EffectDeny  = "deny"
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// Validate checks the configuration for structural and referential errors.
func (c *Config) Validate() error {
	upstreams := map[string]bool{}
	for _, u := range c.Upstreams {
		if !nameRE.MatchString(u.Name) {
			return fmt.Errorf("upstream %q: name must match %s", u.Name, nameRE)
		}
		if upstreams[u.Name] {
			return fmt.Errorf("upstream %q: duplicate name", u.Name)
		}
		upstreams[u.Name] = true
		if _, err := parseBaseURL(u.BaseURL); err != nil {
			return fmt.Errorf("upstream %q: %w", u.Name, err)
		}
		if u.TimeoutSeconds < 0 {
			return fmt.Errorf("upstream %q: timeout_seconds must not be negative", u.Name)
		}
	}

	policies := map[string]bool{}
	for _, p := range c.Policies {
		if !nameRE.MatchString(p.Name) {
			return fmt.Errorf("policy %q: name must match %s", p.Name, nameRE)
		}
		if policies[p.Name] {
			return fmt.Errorf("policy %q: duplicate name", p.Name)
		}
		policies[p.Name] = true
		if !upstreams[p.Upstream] {
			return fmt.Errorf("policy %q: unknown upstream %q", p.Name, p.Upstream)
		}
		for i, r := range p.Rules {
			if r.Effect != EffectAllow && r.Effect != EffectDeny {
				return fmt.Errorf("policy %q rule %d: effect must be %q or %q", p.Name, i+1, EffectAllow, EffectDeny)
			}
			if r.Path != "" && !strings.HasPrefix(r.Path, "/") {
				return fmt.Errorf("policy %q rule %d: path must start with /", p.Name, i+1)
			}
			for k, vs := range r.Params {
				if k == "" {
					return fmt.Errorf("policy %q rule %d: empty parameter name", p.Name, i+1)
				}
				if len(vs) == 0 {
					return fmt.Errorf("policy %q rule %d: parameter %q needs at least one allowed value", p.Name, i+1, k)
				}
			}
		}
	}

	clients := map[string]bool{}
	tokens := map[string]string{}
	for _, cl := range c.Clients {
		if !nameRE.MatchString(cl.Name) {
			return fmt.Errorf("client %q: name must match %s", cl.Name, nameRE)
		}
		if clients[cl.Name] {
			return fmt.Errorf("client %q: duplicate name", cl.Name)
		}
		clients[cl.Name] = true
		for _, pn := range cl.Policies {
			if !policies[pn] {
				return fmt.Errorf("client %q: unknown policy %q", cl.Name, pn)
			}
		}
		for _, ip := range cl.AllowedIPs {
			if _, err := parsePrefix(ip); err != nil {
				return fmt.Errorf("client %q: %w", cl.Name, err)
			}
		}
		if cl.TokenHash != "" {
			if !strings.HasPrefix(cl.TokenHash, tokenHashPrefix) {
				return fmt.Errorf("client %q: token_hash must start with %q", cl.Name, tokenHashPrefix)
			}
			if other, ok := tokens[cl.TokenHash]; ok {
				return fmt.Errorf("client %q: token_hash is shared with client %q", cl.Name, other)
			}
			tokens[cl.TokenHash] = cl.Name
		}
	}
	return nil
}

func parseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("base_url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("base_url: scheme must be http or https")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("base_url: missing host")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("base_url: must not contain a query or fragment")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// resolveSecret expands "env:NAME" and "file:/path" references.
func resolveSecret(v string) (string, error) {
	switch {
	case strings.HasPrefix(v, "env:"):
		name := strings.TrimPrefix(v, "env:")
		s, ok := os.LookupEnv(name)
		if !ok || s == "" {
			return "", fmt.Errorf("environment variable %s is not set", name)
		}
		return s, nil
	case strings.HasPrefix(v, "file:"):
		b, err := os.ReadFile(strings.TrimPrefix(v, "file:"))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	default:
		return v, nil
	}
}

// isSecretRef reports whether v refers to a secret instead of embedding it.
func isSecretRef(v string) bool {
	return strings.HasPrefix(v, "env:") || strings.HasPrefix(v, "file:")
}

func (c *Config) clone() *Config {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	out := &Config{}
	if err := json.Unmarshal(b, out); err != nil {
		panic(err)
	}
	return out
}
