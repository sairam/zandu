package forwarder

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Client authentication methods, as reported in audit entries.
const (
	AuthToken = "token"
	AuthBasic = "basic"
	AuthJWT   = "jwt"
)

var errNoCredentials = errors.New("missing client credentials")

// authenticate identifies the client making r. It accepts, in order:
// the X-Zandu-Token header, "Authorization: Bearer" with a forwarder token or
// a JWT, and "Authorization: Basic" with the client name and token.
func (rt *Runtime) authenticate(ctx context.Context, snap *snapshot, r *http.Request) (*compiledClient, string, error) {
	if t := r.Header.Get(TokenHeader); t != "" {
		return byToken(snap, t)
	}
	scheme, cred, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok {
		return nil, "", errNoCredentials
	}
	cred = strings.TrimSpace(cred)
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		if strings.HasPrefix(cred, tokenPrefix) {
			return byToken(snap, cred)
		}
		if strings.Count(cred, ".") == 2 {
			c, err := rt.verifyJWT(ctx, snap, cred)
			return c, AuthJWT, err
		}
		return nil, "", errors.New("unrecognized bearer token")
	case strings.EqualFold(scheme, "Basic"):
		user, pass, ok := r.BasicAuth()
		if !ok {
			return nil, AuthBasic, errors.New("malformed basic credentials")
		}
		c := snap.byToken[HashToken(pass)]
		if c == nil || c.name != user {
			return nil, AuthBasic, errors.New("invalid basic credentials")
		}
		return c, AuthBasic, nil
	}
	return nil, "", errNoCredentials
}

func byToken(snap *snapshot, t string) (*compiledClient, string, error) {
	c := snap.byToken[HashToken(t)]
	if c == nil {
		return nil, AuthToken, errors.New("invalid client token")
	}
	return c, AuthToken, nil
}

// jwtLeeway tolerates clock skew between the issuer and the forwarder.
const jwtLeeway = 60 * time.Second

func (rt *Runtime) verifyJWT(ctx context.Context, snap *snapshot, raw string) (*compiledClient, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed JWT")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	claims := map[string]any{}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return nil, errors.New("malformed JWT header")
	}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, errors.New("malformed JWT claims")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("malformed JWT signature")
	}

	iss, _ := claims["iss"].(string)
	is := snap.issuers[iss]
	if is == nil {
		return nil, errors.New("JWT issuer is not trusted")
	}

	signed := []byte(parts[0] + "." + parts[1])
	if is.HMACSecret != "" {
		h, ok := hmacAlgs[hdr.Alg]
		if !ok {
			return nil, fmt.Errorf("JWT algorithm %q is not allowed for this issuer", hdr.Alg)
		}
		secret, err := rt.Secrets.Resolve(ctx, is.HMACSecret)
		if err != nil {
			return nil, fmt.Errorf("issuer %q: %w", is.Name, err)
		}
		mac := hmac.New(h.New, []byte(secret))
		mac.Write(signed)
		if !hmac.Equal(mac.Sum(nil), sig) {
			return nil, errors.New("invalid JWT signature")
		}
	} else {
		if _, ok := asymmetricAlgs[hdr.Alg]; !ok {
			return nil, fmt.Errorf("JWT algorithm %q is not allowed for this issuer", hdr.Alg)
		}
		keys, err := rt.jwks.lookup(ctx, rt.HTTPClient, is.JWKSURL, hdr.Kid)
		if err != nil {
			return nil, fmt.Errorf("issuer %q: %w", is.Name, err)
		}
		verified := false
		for _, k := range keys {
			if verifySignature(hdr.Alg, k.pub, signed, sig) {
				verified = true
				break
			}
		}
		if !verified {
			return nil, errors.New("invalid JWT signature")
		}
	}

	now := time.Now()
	exp, ok := numericClaim(claims, "exp")
	if !ok {
		return nil, errors.New("JWT has no exp claim")
	}
	if now.After(exp.Add(jwtLeeway)) {
		return nil, errors.New("JWT has expired")
	}
	if nbf, ok := numericClaim(claims, "nbf"); ok && now.Add(jwtLeeway).Before(nbf) {
		return nil, errors.New("JWT is not valid yet")
	}
	if len(is.Audience) > 0 && !audienceMatches(claims["aud"], is.Audience) {
		return nil, errors.New("JWT audience is not accepted")
	}

	claim := is.SubjectClaim
	if claim == "" {
		claim = "sub"
	}
	sub, _ := claims[claim].(string)
	if sub == "" {
		return nil, fmt.Errorf("JWT has no %s claim", claim)
	}
	c := snap.byIdentity[Identity{Issuer: is.Name, Subject: sub}]
	if c == nil {
		return nil, fmt.Errorf("no client for %s %q from issuer %q", claim, sub, is.Name)
	}
	return c, nil
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func numericClaim(claims map[string]any, name string) (time.Time, bool) {
	f, ok := claims[name].(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

func audienceMatches(aud any, accepted []string) bool {
	var got []string
	switch v := aud.(type) {
	case string:
		got = []string{v}
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				got = append(got, s)
			}
		}
	}
	for _, g := range got {
		for _, a := range accepted {
			if g == a {
				return true
			}
		}
	}
	return false
}

var hmacAlgs = map[string]crypto.Hash{"HS256": crypto.SHA256, "HS384": crypto.SHA384, "HS512": crypto.SHA512}

var asymmetricAlgs = map[string]crypto.Hash{
	"RS256": crypto.SHA256, "RS384": crypto.SHA384, "RS512": crypto.SHA512,
	"PS256": crypto.SHA256, "PS384": crypto.SHA384, "PS512": crypto.SHA512,
	"ES256": crypto.SHA256, "ES384": crypto.SHA384, "ES512": crypto.SHA512,
	"EdDSA": 0,
}

func verifySignature(alg string, key crypto.PublicKey, signed, sig []byte) bool {
	h := asymmetricAlgs[alg]
	var digest []byte
	if h != 0 {
		hh := h.New()
		hh.Write(signed)
		digest = hh.Sum(nil)
	}
	switch k := key.(type) {
	case *rsa.PublicKey:
		switch alg[:2] {
		case "RS":
			return rsa.VerifyPKCS1v15(k, h, digest, sig) == nil
		case "PS":
			return rsa.VerifyPSS(k, h, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
		}
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		want := map[string]int{"ES256": 256, "ES384": 384, "ES512": 521}[alg]
		if want != k.Curve.Params().BitSize || len(sig) != 2*size {
			return false
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		return ecdsa.Verify(k, digest, r, s)
	case ed25519.PublicKey:
		return alg == "EdDSA" && ed25519.Verify(k, signed, sig)
	}
	return false
}

// jwksCache keeps issuers' key sets, refreshing them periodically and when a
// token names an unknown key ID.
type jwksCache struct {
	mu   sync.Mutex
	sets map[string]*jwkSet
}

type jwkSet struct {
	keys        []jwk
	fetched     time.Time
	lastAttempt time.Time
}

type jwk struct {
	kid string
	pub crypto.PublicKey
}

const (
	jwksMaxAge          = 10 * time.Minute
	jwksMinRefreshDelay = 30 * time.Second
)

func (c *jwksCache) lookup(ctx context.Context, client *http.Client, url, kid string) ([]jwk, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sets == nil {
		c.sets = map[string]*jwkSet{}
	}
	set := c.sets[url]
	stale := set == nil || time.Since(set.fetched) > jwksMaxAge
	unknownKid := set != nil && kid != "" && len(set.match(kid)) == 0
	if (stale || unknownKid) && (set == nil || time.Since(set.lastAttempt) > jwksMinRefreshDelay) {
		keys, err := fetchJWKS(ctx, client, url)
		now := time.Now()
		switch {
		case err == nil:
			set = &jwkSet{keys: keys, fetched: now, lastAttempt: now}
			c.sets[url] = set
		case set == nil:
			return nil, fmt.Errorf("fetch JWKS: %w", err)
		default:
			set.lastAttempt = now
		}
	}
	keys := set.match(kid)
	if len(keys) == 0 {
		return nil, errors.New("no matching key in JWKS")
	}
	return keys, nil
}

func (s *jwkSet) match(kid string) []jwk {
	if kid == "" {
		return s.keys
	}
	var out []jwk
	for _, k := range s.keys {
		if k.kid == kid {
			out = append(out, k)
		}
	}
	return out
}

func fetchJWKS(ctx context.Context, client *http.Client, url string) ([]jwk, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", url, resp.Status)
	}
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			Crv string `json:"crv"`
			N   string `json:"n"`
			E   string `json:"e"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	var keys []jwk
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		var pub crypto.PublicKey
		switch k.Kty {
		case "RSA":
			n, e := b64Int(k.N), b64Int(k.E)
			if n == nil || e == nil || !e.IsInt64() {
				continue
			}
			pub = &rsa.PublicKey{N: n, E: int(e.Int64())}
		case "EC":
			curve := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}[k.Crv]
			x, y := b64Int(k.X), b64Int(k.Y)
			if curve == nil || x == nil || y == nil || !curve.IsOnCurve(x, y) {
				continue
			}
			pub = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		case "OKP":
			b, err := base64.RawURLEncoding.DecodeString(k.X)
			if k.Crv != "Ed25519" || err != nil || len(b) != ed25519.PublicKeySize {
				continue
			}
			pub = ed25519.PublicKey(b)
		default:
			continue
		}
		keys = append(keys, jwk{kid: k.Kid, pub: pub})
	}
	if len(keys) == 0 {
		return nil, errors.New("JWKS contains no usable signing keys")
	}
	return keys, nil
}

func b64Int(s string) *big.Int {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil
	}
	return new(big.Int).SetBytes(b)
}
