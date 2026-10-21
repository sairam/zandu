package forwarder

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

//go:embed ui
var uiFiles embed.FS

// maskedSecret replaces literal credential values in admin API responses.
// Sending it back unchanged keeps the stored value.
const maskedSecret = "********"

var errNotFound = errors.New("not found")

// Admin serves the management UI and its JSON API. Every API call requires
// "Authorization: Bearer <admin token>".
type Admin struct {
	store *Store
	audit *AuditLog
	token string
	mux   *http.ServeMux
}

// NewAdmin returns the admin handler. token must not be empty.
func NewAdmin(store *Store, audit *AuditLog, token string) *Admin {
	a := &Admin{store: store, audit: audit, token: token, mux: http.NewServeMux()}

	ui, _ := fs.Sub(uiFiles, "ui")
	a.mux.Handle("GET /", http.FileServerFS(ui))

	a.mux.HandleFunc("GET /api/config", a.auth(a.getConfig))
	a.mux.HandleFunc("PUT /api/upstreams/{name}", a.auth(a.putUpstream))
	a.mux.HandleFunc("DELETE /api/upstreams/{name}", a.auth(a.deleteUpstream))
	a.mux.HandleFunc("PUT /api/policies/{name}", a.auth(a.putPolicy))
	a.mux.HandleFunc("DELETE /api/policies/{name}", a.auth(a.deletePolicy))
	a.mux.HandleFunc("PUT /api/clients/{name}", a.auth(a.putClient))
	a.mux.HandleFunc("DELETE /api/clients/{name}", a.auth(a.deleteClient))
	a.mux.HandleFunc("POST /api/clients/{name}/token", a.auth(a.rotateToken))
	a.mux.HandleFunc("GET /api/presets", a.auth(a.listPresets))
	a.mux.HandleFunc("POST /api/presets/{id}", a.auth(a.applyPreset))
	a.mux.HandleFunc("POST /api/evaluate", a.auth(a.evaluate))
	a.mux.HandleFunc("GET /api/audit", a.auth(a.getAudit))
	return a
}

func (a *Admin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	a.mux.ServeHTTP(w, r)
}

func (a *Admin) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := ""
		if scheme, t, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "Bearer") {
			tok = strings.TrimSpace(t)
		}
		if a.token == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(a.token)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid admin token")
			return
		}
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		next(w, r)
	}
}

// clientView is a Client as exposed by the admin API, without its token hash.
type clientView struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Policies    []string `json:"policies"`
	AllowedIPs  []string `json:"allowed_ips,omitempty"`
	Disabled    bool     `json:"disabled,omitempty"`
	HasToken    bool     `json:"has_token"`
}

type configView struct {
	Upstreams []Upstream   `json:"upstreams"`
	Policies  []Policy     `json:"policies"`
	Clients   []clientView `json:"clients"`
}

func (a *Admin) getConfig(w http.ResponseWriter, r *http.Request) {
	cfg := a.store.Config()
	v := configView{Upstreams: []Upstream{}, Policies: []Policy{}, Clients: []clientView{}}
	for _, u := range cfg.Upstreams {
		u.Inject.Query = maskSecrets(u.Inject.Query)
		u.Inject.Headers = maskSecrets(u.Inject.Headers)
		v.Upstreams = append(v.Upstreams, u)
	}
	for _, p := range cfg.Policies {
		if p.Rules == nil {
			p.Rules = []Rule{}
		}
		v.Policies = append(v.Policies, p)
	}
	for _, c := range cfg.Clients {
		v.Clients = append(v.Clients, viewClient(c))
	}
	writeJSON(w, http.StatusOK, v)
}

func viewClient(c Client) clientView {
	if c.Policies == nil {
		c.Policies = []string{}
	}
	return clientView{
		Name: c.Name, Description: c.Description, Policies: c.Policies,
		AllowedIPs: c.AllowedIPs, Disabled: c.Disabled, HasToken: c.TokenHash != "",
	}
}

func maskSecrets(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if isSecretRef(v) {
			out[k] = v
		} else {
			out[k] = maskedSecret
		}
	}
	return out
}

// unmaskSecrets restores stored values for keys sent back masked.
func unmaskSecrets(in, old map[string]string) (map[string]string, error) {
	for k, v := range in {
		if v != maskedSecret {
			continue
		}
		prev, ok := old[k]
		if !ok {
			return nil, fmt.Errorf("%q has no stored value to keep", k)
		}
		in[k] = prev
	}
	return in, nil
}

func (a *Admin) putUpstream(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var u Upstream
	if !readJSON(w, r, &u) {
		return
	}
	u.Name = name
	err := a.store.Update(func(c *Config) error {
		i := indexOf(c.Upstreams, func(x Upstream) bool { return x.Name == name })
		var old Upstream
		if i >= 0 {
			old = c.Upstreams[i]
		}
		var err error
		if u.Inject.Query, err = unmaskSecrets(u.Inject.Query, old.Inject.Query); err != nil {
			return fmt.Errorf("inject query: %w", err)
		}
		if u.Inject.Headers, err = unmaskSecrets(u.Inject.Headers, old.Inject.Headers); err != nil {
			return fmt.Errorf("inject headers: %w", err)
		}
		c.Upstreams = upsert(c.Upstreams, i, u)
		return nil
	})
	a.respond(w, err, nil)
}

func (a *Admin) deleteUpstream(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := a.store.Update(func(c *Config) error {
		var ok bool
		c.Upstreams, ok = remove(c.Upstreams, func(x Upstream) bool { return x.Name == name })
		if !ok {
			return errNotFound
		}
		return nil
	})
	a.respond(w, err, nil)
}

func (a *Admin) putPolicy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var p Policy
	if !readJSON(w, r, &p) {
		return
	}
	p.Name = name
	err := a.store.Update(func(c *Config) error {
		i := indexOf(c.Policies, func(x Policy) bool { return x.Name == name })
		c.Policies = upsert(c.Policies, i, p)
		return nil
	})
	a.respond(w, err, nil)
}

func (a *Admin) deletePolicy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := a.store.Update(func(c *Config) error {
		var ok bool
		c.Policies, ok = remove(c.Policies, func(x Policy) bool { return x.Name == name })
		if !ok {
			return errNotFound
		}
		return nil
	})
	a.respond(w, err, nil)
}

// putClient creates or updates a client. A new client receives a token,
// which is returned once in the response.
func (a *Admin) putClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var in clientView
	if !readJSON(w, r, &in) {
		return
	}
	var token string
	err := a.store.Update(func(c *Config) error {
		i := indexOf(c.Clients, func(x Client) bool { return x.Name == name })
		cl := Client{
			Name: name, Description: in.Description, Policies: in.Policies,
			AllowedIPs: in.AllowedIPs, Disabled: in.Disabled,
		}
		if i >= 0 {
			cl.TokenHash = c.Clients[i].TokenHash
		} else {
			var hash string
			var err error
			if token, hash, err = NewToken(); err != nil {
				return err
			}
			cl.TokenHash = hash
		}
		c.Clients = upsert(c.Clients, i, cl)
		return nil
	})
	var resp any
	if token != "" {
		resp = map[string]string{"token": token}
	}
	a.respond(w, err, resp)
}

func (a *Admin) deleteClient(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := a.store.Update(func(c *Config) error {
		var ok bool
		c.Clients, ok = remove(c.Clients, func(x Client) bool { return x.Name == name })
		if !ok {
			return errNotFound
		}
		return nil
	})
	a.respond(w, err, nil)
}

func (a *Admin) rotateToken(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	token, hash, err := NewToken()
	if err != nil {
		a.respond(w, err, nil)
		return
	}
	err = a.store.Update(func(c *Config) error {
		i := indexOf(c.Clients, func(x Client) bool { return x.Name == name })
		if i < 0 {
			return errNotFound
		}
		c.Clients[i].TokenHash = hash
		return nil
	})
	a.respond(w, err, map[string]string{"token": token})
}

func (a *Admin) listPresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, Presets())
}

// applyPreset adds a preset's upstream and policies. Existing objects with the
// same names are left untouched and reported as skipped.
func (a *Admin) applyPreset(w http.ResponseWriter, r *http.Request) {
	p, ok := PresetByID(r.PathValue("id"))
	if !ok {
		a.respond(w, errNotFound, nil)
		return
	}
	var added, skipped []string
	err := a.store.Update(func(c *Config) error {
		if indexOf(c.Upstreams, func(x Upstream) bool { return x.Name == p.Upstream.Name }) >= 0 {
			skipped = append(skipped, "upstream "+p.Upstream.Name)
		} else {
			c.Upstreams = append(c.Upstreams, p.Upstream)
			added = append(added, "upstream "+p.Upstream.Name)
		}
		for _, pol := range p.Policies {
			if indexOf(c.Policies, func(x Policy) bool { return x.Name == pol.Name }) >= 0 {
				skipped = append(skipped, "policy "+pol.Name)
				continue
			}
			c.Policies = append(c.Policies, pol)
			added = append(added, "policy "+pol.Name)
		}
		return nil
	})
	a.respond(w, err, map[string][]string{"added": added, "skipped": skipped})
}

type evaluateRequest struct {
	Client string `json:"client"`
	Method string `json:"method"`
	// URL is the path and query as sent to the proxy, e.g.
	// "/dynadot/api3.json?command=get_dns&domain=example.com".
	URL string `json:"url"`
	// Body is an optional application/x-www-form-urlencoded body.
	Body string `json:"body,omitempty"`
}

type evaluateResponse struct {
	Upstream string     `json:"upstream"`
	Path     string     `json:"path"`
	Params   url.Values `json:"params"`
	Decision Decision   `json:"decision"`
}

// evaluate dry-runs a request against a client's policies without
// forwarding it.
func (a *Admin) evaluate(w http.ResponseWriter, r *http.Request) {
	var in evaluateRequest
	if !readJSON(w, r, &in) {
		return
	}
	if in.Method == "" {
		in.Method = http.MethodGet
	}
	u, err := url.Parse(in.URL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "url could not be parsed")
		return
	}
	snap := a.store.snapshot()
	cl, ok := snap.clients[in.Client]
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", "unknown client")
		return
	}
	name, rest := splitUpstream(u.Path)
	up, ok := snap.upstreams[name]
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("unknown upstream %q", name))
		return
	}
	clean, _ := cleanRequestPath(rest)
	params := url.Values{}
	for _, raw := range []string{u.RawQuery, in.Body} {
		v, err := url.ParseQuery(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "parameters could not be parsed")
			return
		}
		stripParams(v, up.query)
		mergeValues(params, v)
	}
	d := evaluate(cl.policies, name, Request{Method: in.Method, Path: clean, Params: params})
	if cl.disabled {
		d = Decision{Allowed: false, Reason: "client is disabled"}
	}
	writeJSON(w, http.StatusOK, evaluateResponse{Upstream: name, Path: clean, Params: params, Decision: d})
}

func (a *Admin) getAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	writeJSON(w, http.StatusOK, a.audit.Recent(limit))
}

func (a *Admin) respond(w http.ResponseWriter, err error, body any) {
	switch {
	case errors.Is(err, errNotFound):
		writeError(w, http.StatusNotFound, "not_found", "not found")
	case err != nil:
		writeError(w, http.StatusBadRequest, "invalid", err.Error())
	case body != nil:
		writeJSON(w, http.StatusOK, body)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func indexOf[T any](s []T, match func(T) bool) int {
	for i, x := range s {
		if match(x) {
			return i
		}
	}
	return -1
}

func upsert[T any](s []T, i int, v T) []T {
	if i >= 0 {
		s[i] = v
		return s
	}
	return append(s, v)
}

func remove[T any](s []T, match func(T) bool) ([]T, bool) {
	i := indexOf(s, match)
	if i < 0 {
		return s, false
	}
	return append(s[:i], s[i+1:]...), true
}
