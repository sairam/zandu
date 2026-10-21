package forwarder

import (
	"net/url"
	"testing"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"", "", true},
		{"*", "", true},
		{"*", "anything", true},
		{"abc", "abc", true},
		{"abc", "abcd", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "example.com", false},
		{"domain*", "domain0", true},
		{"domain*", "domain", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
		{"get_*", "get_dns", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestMatchSegments(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"/", "/", true},
		{"/", "/a", false},
		{"/api3.*", "/api3.json", true},
		{"/api3.*", "/api3.json/x", false},
		{"/v1/*/records", "/v1/example.com/records", true},
		{"/v1/*/records", "/v1/a/b/records", false},
		{"/v1/**", "/v1", true},
		{"/v1/**", "/v1/a/b/c", true},
		{"/**/records", "/a/b/records", true},
		{"/**/records", "/a/b/other", false},
	}
	for _, c := range cases {
		if got := matchSegments(splitPath(c.pattern), splitPath(c.path)); got != c.want {
			t.Errorf("matchSegments(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func eval(t *testing.T, policies []Policy, method, rawURL string) Decision {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	var compiled []*compiledPolicy
	for _, p := range policies {
		cp := compilePolicy(p)
		compiled = append(compiled, &cp)
	}
	return evaluate(compiled, "api", Request{Method: method, Path: u.Path, Params: u.Query()})
}

func TestEvaluate(t *testing.T) {
	dns := Policy{Name: "dns", Upstream: "api", Rules: []Rule{{
		Effect:  EffectAllow,
		Methods: []string{"GET"},
		Path:    "/api3.json",
		Params: map[string][]string{
			"command": {"get_dns", "set_dns2"},
			"domain":  {"example.com", "*.example.com"},
		},
	}}}
	search := Policy{Name: "search", Upstream: "api", Rules: []Rule{
		{Effect: EffectAllow, Params: map[string][]string{"command": {"search"}, "domain*": {"*"}}},
		{Effect: EffectDeny, Params: map[string][]string{"domain*": {"*.internal"}}},
	}}
	other := Policy{Name: "other", Upstream: "elsewhere", Rules: []Rule{{Effect: EffectAllow}}}

	cases := []struct {
		name     string
		policies []Policy
		method   string
		url      string
		allowed  bool
	}{
		{"allowed command and domain", []Policy{dns}, "GET", "/api3.json?command=get_dns&domain=example.com", true},
		{"subdomain glob", []Policy{dns}, "GET", "/api3.json?command=set_dns2&domain=a.example.com", true},
		{"case-insensitive", []Policy{dns}, "GET", "/API3.JSON?Command=GET_DNS&DOMAIN=Example.COM", true},
		{"other domain", []Policy{dns}, "GET", "/api3.json?command=get_dns&domain=evil.com", false},
		{"other command", []Policy{dns}, "GET", "/api3.json?command=delete&domain=example.com", false},
		{"missing required param", []Policy{dns}, "GET", "/api3.json?command=get_dns", false},
		{"duplicate param smuggling", []Policy{dns}, "GET", "/api3.json?command=get_dns&command=delete&domain=example.com", false},
		{"case variant smuggling", []Policy{dns}, "GET", "/api3.json?command=get_dns&COMMAND=delete&domain=example.com", false},
		{"wrong method", []Policy{dns}, "POST", "/api3.json?command=get_dns&domain=example.com", false},
		{"wrong path", []Policy{dns}, "GET", "/api3.xml?command=get_dns&domain=example.com", false},
		{"wildcard param names", []Policy{search}, "GET", "/api3.json?command=search&domain0=a.com&domain1=b.com", true},
		{"wildcard param absent is fine", []Policy{search}, "GET", "/api3.json?command=search", true},
		{"deny overrides allow", []Policy{search}, "GET", "/api3.json?command=search&domain0=a.com&domain1=b.internal", false},
		{"deny fires on any value", []Policy{search}, "GET", "/api3.json?command=search&domain0=a.com&domain0=b.internal", false},
		{"policy for other upstream ignored", []Policy{other}, "GET", "/anything", false},
		{"no policies", nil, "GET", "/", false},
		{"first allowing policy wins", []Policy{dns, search}, "GET", "/api3.json?command=search&domain0=x.com", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := eval(t, c.policies, c.method, c.url)
			if d.Allowed != c.allowed {
				t.Fatalf("allowed = %v, want %v (%s)", d.Allowed, c.allowed, d.Reason)
			}
		})
	}
}

func TestEvaluateReportsRule(t *testing.T) {
	p := Policy{Name: "p", Upstream: "api", Rules: []Rule{
		{Effect: EffectAllow, Path: "/a"},
		{Effect: EffectDeny, Path: "/b"},
	}}
	d := eval(t, []Policy{p}, "GET", "/b")
	if d.Allowed || d.Policy != "p" || d.Rule != 2 {
		t.Fatalf("got %+v", d)
	}
}
