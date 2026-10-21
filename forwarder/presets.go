package forwarder

// Preset is a ready-made upstream definition with starter policies for a
// well-known API. Policies use example.com as a placeholder domain that is
// meant to be edited after the preset is added.
type Preset struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	DocsURL     string   `json:"docs_url"`
	Env         []string `json:"env"`
	Upstream    Upstream `json:"upstream"`
	Policies    []Policy `json:"policies"`
}

// Presets returns the built-in presets.
func Presets() []Preset {
	return []Preset{dynadotPreset(), namecheapPreset()}
}

// PresetByID returns the preset with the given id.
func PresetByID(id string) (Preset, bool) {
	for _, p := range Presets() {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

// dynadotPreset covers the Dynadot API3 interface, which authenticates with a
// single account-wide key restricted to an IP allowlist. Every call is a GET
// to /api3.json or /api3.xml with the operation in the "command" parameter.
func dynadotPreset() Preset {
	paths := "/api3.*"
	return Preset{
		ID:          "dynadot",
		Title:       "Dynadot API3",
		Description: "Domain registrar API authenticated by an account-wide key and an IP allowlist.",
		DocsURL:     "https://www.dynadot.com/domain/api3.html",
		Env:         []string{"DYNADOT_API_KEY"},
		Upstream: Upstream{
			Name:        "dynadot",
			Description: "Dynadot API3",
			BaseURL:     "https://api.dynadot.com",
			Inject: Inject{
				Query: map[string]string{"key": "env:DYNADOT_API_KEY"},
			},
		},
		Policies: []Policy{
			{
				Name:        "dynadot-read-only",
				Description: "Read-only account, domain and DNS lookups.",
				Upstream:    "dynadot",
				Rules: []Rule{{
					Effect:  EffectAllow,
					Methods: []string{"GET"},
					Path:    paths,
					Params: map[string][]string{"command": {
						"search", "domain_info", "list_domain", "get_dns",
						"get_ns", "account_info", "get_contact", "contact_list",
						"is_processing", "get_transfer_status", "tld_price",
					}},
				}},
			},
			{
				Name:        "dynadot-dns-example-com",
				Description: "Read and update DNS records of example.com only.",
				Upstream:    "dynadot",
				Rules: []Rule{{
					Effect:  EffectAllow,
					Methods: []string{"GET"},
					Path:    paths,
					Params: map[string][]string{
						"command": {"domain_info", "get_dns", "set_dns2"},
						"domain":  {"example.com"},
					},
				}},
			},
		},
	}
}

// namecheapPreset covers the Namecheap XML API. Calls go to /xml.response
// with the operation in "Command"; authentication uses ApiUser, ApiKey,
// UserName and ClientIp parameters, and the caller's IP must be allowlisted.
// Domains are addressed either as SLD and TLD or as DomainName depending on
// the command. Use https://api.sandbox.namecheap.com for testing.
func namecheapPreset() Preset {
	return Preset{
		ID:          "namecheap",
		Title:       "Namecheap API",
		Description: "Domain registrar API authenticated by API user, key and an IP allowlist.",
		DocsURL:     "https://www.namecheap.com/support/api/methods/",
		Env:         []string{"NAMECHEAP_API_USER", "NAMECHEAP_API_KEY", "NAMECHEAP_USERNAME", "NAMECHEAP_CLIENT_IP"},
		Upstream: Upstream{
			Name:        "namecheap",
			Description: "Namecheap XML API",
			BaseURL:     "https://api.namecheap.com",
			Inject: Inject{
				Query: map[string]string{
					"ApiUser":  "env:NAMECHEAP_API_USER",
					"ApiKey":   "env:NAMECHEAP_API_KEY",
					"UserName": "env:NAMECHEAP_USERNAME",
					"ClientIp": "env:NAMECHEAP_CLIENT_IP",
				},
			},
		},
		Policies: []Policy{
			{
				Name:        "namecheap-read-only",
				Description: "Read-only account, domain and DNS lookups.",
				Upstream:    "namecheap",
				Rules: []Rule{{
					Effect:  EffectAllow,
					Methods: []string{"GET"},
					Path:    "/xml.response",
					Params: map[string][]string{"Command": {
						"namecheap.domains.getList", "namecheap.domains.getInfo",
						"namecheap.domains.check", "namecheap.domains.getContacts",
						"namecheap.domains.getTldList", "namecheap.domains.dns.getHosts",
						"namecheap.domains.dns.getList", "namecheap.domains.dns.getEmailForwarding",
						"namecheap.domains.ns.getInfo", "namecheap.users.getBalances",
						"namecheap.users.getPricing",
					}},
				}},
			},
			{
				Name:        "namecheap-dns-example-com",
				Description: "Read and update DNS records of example.com only.",
				Upstream:    "namecheap",
				Rules: []Rule{
					{
						Effect:      EffectAllow,
						Description: "Host records, addressed by SLD and TLD. setHosts may be sent as a form POST.",
						Methods:     []string{"GET", "POST"},
						Path:        "/xml.response",
						Params: map[string][]string{
							"Command": {"namecheap.domains.dns.getHosts", "namecheap.domains.dns.setHosts", "namecheap.domains.dns.getList"},
							"SLD":     {"example"},
							"TLD":     {"com"},
						},
					},
					{
						Effect:      EffectAllow,
						Description: "Domain details, addressed by DomainName.",
						Methods:     []string{"GET"},
						Path:        "/xml.response",
						Params: map[string][]string{
							"Command":    {"namecheap.domains.getInfo"},
							"DomainName": {"example.com"},
						},
					},
				},
			},
		},
	}
}
