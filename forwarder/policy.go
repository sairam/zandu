package forwarder

import (
	"fmt"
	"net/url"
	"strings"
)

// Request is the part of an incoming request that policies are evaluated on.
type Request struct {
	Method string
	// Path is the cleaned path relative to the upstream base URL.
	Path string
	// Params holds query parameters merged with form-encoded body parameters.
	Params url.Values
}

// Decision is the outcome of evaluating a request against a client's policies.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
	Policy  string `json:"policy,omitempty"`
	// Rule is the 1-based index of the matching rule within Policy.
	Rule int `json:"rule,omitempty"`
}

type compiledRule struct {
	effect  string
	methods map[string]bool
	path    []string
	params  []paramConstraint
	index   int
}

type paramConstraint struct {
	name     string
	wildcard bool
	values   []string
}

type compiledPolicy struct {
	name     string
	upstream string
	rules    []compiledRule
}

func compilePolicy(p Policy) compiledPolicy {
	cp := compiledPolicy{name: p.Name, upstream: p.Upstream}
	for i, r := range p.Rules {
		cr := compiledRule{effect: r.Effect, index: i + 1}
		if len(r.Methods) > 0 {
			cr.methods = map[string]bool{}
			for _, m := range r.Methods {
				cr.methods[strings.ToUpper(strings.TrimSpace(m))] = true
			}
		}
		if r.Path != "" {
			cr.path = splitPath(strings.ToLower(r.Path))
		}
		for k, vs := range r.Params {
			pc := paramConstraint{
				name:     strings.ToLower(k),
				wildcard: strings.ContainsAny(k, "*?"),
			}
			for _, v := range vs {
				pc.values = append(pc.values, strings.ToLower(v))
			}
			cr.params = append(cr.params, pc)
		}
		cp.rules = append(cp.rules, cr)
	}
	return cp
}

// normalizeRequest lower-cases the path and parameter names and values so
// that matching is case-insensitive. Values of parameters that differ only in
// case are merged, so a request cannot smuggle "command" past a rule on
// "Command".
func normalizeRequest(r Request) (method string, path []string, params map[string][]string) {
	params = map[string][]string{}
	for k, vs := range r.Params {
		lk := strings.ToLower(k)
		for _, v := range vs {
			params[lk] = append(params[lk], strings.ToLower(v))
		}
	}
	return strings.ToUpper(r.Method), splitPath(strings.ToLower(r.Path)), params
}

func (cr *compiledRule) matches(method string, path []string, params map[string][]string) bool {
	if cr.methods != nil && !cr.methods[method] {
		return false
	}
	if cr.path != nil && !matchSegments(cr.path, path) {
		return false
	}
	for _, pc := range cr.params {
		if cr.effect == EffectDeny {
			if !pc.matchesAnyValue(params) {
				return false
			}
		} else if !pc.matchesAllValues(params) {
			return false
		}
	}
	return true
}

// matchesAllValues is the allow-rule check: every value of every parameter
// named by the constraint must be allowed, and a parameter named without
// wildcards must be present.
func (pc *paramConstraint) matchesAllValues(params map[string][]string) bool {
	found := false
	for name, values := range params {
		if !globMatch(pc.name, name) {
			continue
		}
		found = true
		for _, v := range values {
			if !matchAny(pc.values, v) {
				return false
			}
		}
	}
	return found || pc.wildcard
}

// matchesAnyValue is the deny-rule check: a single matching value of any
// parameter named by the constraint is enough.
func (pc *paramConstraint) matchesAnyValue(params map[string][]string) bool {
	for name, values := range params {
		if !globMatch(pc.name, name) {
			continue
		}
		for _, v := range values {
			if matchAny(pc.values, v) {
				return true
			}
		}
	}
	return false
}

// evaluate applies deny-overrides semantics: any matching deny rule denies,
// otherwise any matching allow rule allows, otherwise the request is denied.
func evaluate(policies []*compiledPolicy, upstream string, r Request) Decision {
	method, path, params := normalizeRequest(r)
	var allow *Decision
	for _, p := range policies {
		if p.upstream != upstream {
			continue
		}
		for i := range p.rules {
			cr := &p.rules[i]
			if !cr.matches(method, path, params) {
				continue
			}
			if cr.effect == EffectDeny {
				return Decision{
					Allowed: false,
					Reason:  fmt.Sprintf("denied by policy %q rule %d", p.name, cr.index),
					Policy:  p.name,
					Rule:    cr.index,
				}
			}
			if allow == nil {
				allow = &Decision{
					Allowed: true,
					Reason:  fmt.Sprintf("allowed by policy %q rule %d", p.name, cr.index),
					Policy:  p.name,
					Rule:    cr.index,
				}
			}
		}
	}
	if allow != nil {
		return *allow
	}
	return Decision{Allowed: false, Reason: "no policy allows this request"}
}

func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return []string{}
	}
	return strings.Split(p, "/")
}

// matchSegments matches path segments against a pattern in which "*" matches
// within one segment and "**" matches any number of segments.
func matchSegments(pattern, segs []string) bool {
	if len(pattern) == 0 {
		return len(segs) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if matchSegments(pattern[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 || !globMatch(pattern[0], segs[0]) {
		return false
	}
	return matchSegments(pattern[1:], segs[1:])
}

func matchAny(patterns []string, s string) bool {
	for _, p := range patterns {
		if globMatch(p, s) {
			return true
		}
	}
	return false
}

// globMatch reports whether s matches pattern, where "*" matches any
// sequence of characters and "?" matches exactly one.
func globMatch(pattern, s string) bool {
	p, n := []rune(pattern), []rune(s)
	pi, ni := 0, 0
	star, mark := -1, 0
	for ni < len(n) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == n[ni]):
			pi++
			ni++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ni
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ni = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
