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
	"regexp"
	"strings"
)

// Config is the persisted forwarder configuration.
type Config struct {
	Issuers   []Issuer   `json:"issuers,omitempty"`
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
	// Inject lists parameters and headers added to every forwarded request.
	// Values may be literals or secret references (env:, file:, vault:).
	Inject Inject `json:"inject,omitempty"`
	// Auth configures a standard authentication scheme for the upstream.
	Auth *UpstreamAuth `json:"auth,omitempty"`
	// TimeoutSeconds bounds each upstream request. Zero means 30 seconds.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// Inject holds credentials the forwarder adds to upstream requests.
// Client-supplied values for the same names are always replaced.
type Inject struct {
	Query   map[string]string `json:"query,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// Outgoing authentication schemes for UpstreamAuth.Type.
const (
	UpstreamAuthBasic             = "basic"
	UpstreamAuthBearer            = "bearer"
	UpstreamAuthClientCredentials = "oauth2_client_credentials"
)

// UpstreamAuth authenticates forwarded requests with a standard scheme. It
// complements Inject, which covers API keys sent as parameters or headers.
// Every string field except Type, TokenURL, Scopes and Audience may be a
// secret reference.
type UpstreamAuth struct {
	Type string `json:"type"`
	// basic
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// bearer
	Token string `json:"token,omitempty"`
	// oauth2_client_credentials
	TokenURL     string   `json:"token_url,omitempty"`
	ClientID     string   `json:"client_id,omitempty"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
	Audience     string   `json:"audience,omitempty"`
	// ClientAuthInBody sends the client credentials as form fields instead
	// of HTTP Basic authentication, for servers that require it.
	ClientAuthInBody bool `json:"client_auth_in_body,omitempty"`
}

// Issuer is a trusted JWT issuer, such as an OAuth2 authorization server
// issuing client-credentials tokens. Clients are matched by a claim value.
type Issuer struct {
	Name string `json:"name"`
	// Issuer is the expected "iss" claim.
	Issuer string `json:"issuer"`
	// Audience, if set, requires the "aud" claim to contain one of these.
	Audience []string `json:"audience,omitempty"`
	// JWKSURL verifies asymmetric signatures (RS*, PS*, ES*, EdDSA).
	JWKSURL string `json:"jwks_url,omitempty"`
	// HMACSecret verifies HS* signatures. It may be a secret reference.
	HMACSecret string `json:"hmac_secret,omitempty"`
	// SubjectClaim names the claim that identifies the client. Default
	// "sub"; "client_id" and "azp" are common for client credentials.
	SubjectClaim string `json:"subject_claim,omitempty"`
}

// Identity binds a JWT subject from an issuer to a client.
type Identity struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
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
//
// A client authenticates with its forwarder-issued token (sent as a bearer
// token, in the X-Zandu-Token header, or as the password of HTTP Basic
// authentication with the client name as user), or with a JWT from a
// configured issuer that matches one of its identities.
type Client struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	TokenHash   string     `json:"token_hash,omitempty"`
	Identities  []Identity `json:"identities,omitempty"`
	Policies    []string   `json:"policies"`
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
	issuers := map[string]bool{}
	issuerIDs := map[string]bool{}
	for _, is := range c.Issuers {
		if !nameRE.MatchString(is.Name) {
			return fmt.Errorf("issuer %q: name must match %s", is.Name, nameRE)
		}
		if issuers[is.Name] {
			return fmt.Errorf("issuer %q: duplicate name", is.Name)
		}
		issuers[is.Name] = true
		if is.Issuer == "" {
			return fmt.Errorf("issuer %q: issuer is required", is.Name)
		}
		if issuerIDs[is.Issuer] {
			return fmt.Errorf("issuer %q: another issuer has the same iss value", is.Name)
		}
		issuerIDs[is.Issuer] = true
		if (is.JWKSURL == "") == (is.HMACSecret == "") {
			return fmt.Errorf("issuer %q: set exactly one of jwks_url and hmac_secret", is.Name)
		}
		if is.JWKSURL != "" {
			if u, err := url.Parse(is.JWKSURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return fmt.Errorf("issuer %q: invalid jwks_url", is.Name)
			}
		}
		if err := validateSecretRef(is.HMACSecret); err != nil {
			return fmt.Errorf("issuer %q: hmac_secret: %w", is.Name, err)
		}
	}

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
		for _, m := range []map[string]string{u.Inject.Query, u.Inject.Headers} {
			for k, v := range m {
				if k == "" {
					return fmt.Errorf("upstream %q: empty inject name", u.Name)
				}
				if err := validateSecretRef(v); err != nil {
					return fmt.Errorf("upstream %q: inject %q: %w", u.Name, k, err)
				}
			}
		}
		if err := u.Auth.validate(); err != nil {
			return fmt.Errorf("upstream %q: auth: %w", u.Name, err)
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
	identities := map[Identity]string{}
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
		for _, id := range cl.Identities {
			if !issuers[id.Issuer] {
				return fmt.Errorf("client %q: unknown issuer %q", cl.Name, id.Issuer)
			}
			if id.Subject == "" {
				return fmt.Errorf("client %q: identity for issuer %q needs a subject", cl.Name, id.Issuer)
			}
			if other, ok := identities[id]; ok {
				return fmt.Errorf("client %q: identity %s/%s is already used by client %q", cl.Name, id.Issuer, id.Subject, other)
			}
			identities[id] = cl.Name
		}
	}
	return nil
}

func (a *UpstreamAuth) validate() error {
	if a == nil {
		return nil
	}
	required := map[string]string{}
	switch a.Type {
	case UpstreamAuthBasic:
		required = map[string]string{"username": a.Username, "password": a.Password}
	case UpstreamAuthBearer:
		required = map[string]string{"token": a.Token}
	case UpstreamAuthClientCredentials:
		required = map[string]string{"token_url": a.TokenURL, "client_id": a.ClientID, "client_secret": a.ClientSecret}
		if u, err := url.Parse(a.TokenURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("invalid token_url")
		}
	default:
		return fmt.Errorf("type must be %q, %q or %q", UpstreamAuthBasic, UpstreamAuthBearer, UpstreamAuthClientCredentials)
	}
	for k, v := range required {
		if v == "" {
			return fmt.Errorf("%s is required for %s", k, a.Type)
		}
		if err := validateSecretRef(v); err != nil {
			return fmt.Errorf("%s: %w", k, err)
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
