package forwarder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"
)

// TokenHeader is an alternative to "Authorization: Bearer" for clients
// whose upstream API already uses the Authorization header.
const TokenHeader = "X-Zandu-Token"

// HealthPath is served by the proxy listener without authentication.
const HealthPath = "/_zandu/healthz"

// ProxyOptions configures a Proxy.
type ProxyOptions struct {
	// TrustedProxies lists the networks of load balancers whose
	// X-Forwarded-For header is used to determine the client address.
	TrustedProxies []netip.Prefix
	// MaxBodyBytes bounds form-encoded bodies that are inspected by
	// policies. Zero means 1 MiB.
	MaxBodyBytes int64
	// Transport is used for upstream requests. Nil means
	// http.DefaultTransport.
	Transport http.RoundTripper
	// Runtime resolves secrets and authenticates clients. Nil means a
	// runtime with env and file secrets cached for one minute.
	Runtime *Runtime
	Logger  *slog.Logger
}

// Proxy authenticates clients, evaluates policies and forwards allowed
// requests. Requests are addressed as /{upstream}/{path}.
type Proxy struct {
	store *Store
	audit *AuditLog
	opts  ProxyOptions
}

// NewProxy returns a proxy that reads its configuration from store and
// records decisions in audit.
func NewProxy(store *Store, audit *AuditLog, opts ProxyOptions) *Proxy {
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 1 << 20
	}
	if opts.Transport == nil {
		opts.Transport = http.DefaultTransport
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Runtime == nil {
		opts.Runtime = NewRuntime(NewSecrets(time.Minute, opts.Logger))
	}
	return &Proxy{store: store, audit: audit, opts: opts}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == HealthPath {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
		return
	}

	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w}
	entry := AuditEntry{Time: start.UTC(), Method: r.Method, Path: r.URL.Path}
	clientIP := p.clientIP(r)
	if clientIP.IsValid() {
		entry.RemoteIP = clientIP.String()
	}
	defer func() {
		entry.Status = rec.status
		entry.DurationMS = time.Since(start).Milliseconds()
		p.audit.Add(entry)
		p.opts.Logger.Info("request",
			"client", entry.Client, "auth", entry.AuthMethod, "upstream", entry.Upstream,
			"method", entry.Method, "path", entry.Path, "query", entry.Query,
			"remote_ip", entry.RemoteIP, "allowed", entry.Allowed,
			"reason", entry.Reason, "status", entry.Status,
			"duration_ms", entry.DurationMS)
	}()

	deny := func(status int, code, msg string) {
		entry.Reason = msg
		writeError(rec, status, code, msg)
	}

	snap := p.store.snapshot()

	name, rest := splitUpstream(r.URL.Path)
	up, ok := snap.upstreams[name]
	if !ok {
		deny(http.StatusNotFound, "unknown_upstream", "no upstream is configured for this path")
		return
	}
	entry.Upstream = name
	cleanPath, fwdPath := cleanRequestPath(rest)
	entry.Path = cleanPath

	client, method, err := p.opts.Runtime.authenticate(r.Context(), snap, r)
	entry.AuthMethod = method
	if err != nil {
		// The client gets a generic message; the audit log keeps the cause.
		rec.Header().Set("WWW-Authenticate", `Bearer realm="zandu"`)
		writeError(rec, http.StatusUnauthorized, "unauthorized", "missing or invalid client credentials")
		entry.Reason = err.Error()
		return
	}
	entry.Client = client.name
	if client.disabled {
		deny(http.StatusForbidden, "client_disabled", "client is disabled")
		return
	}
	if !clientIP.IsValid() || !client.ipAllowed(clientIP) {
		deny(http.StatusForbidden, "ip_not_allowed", "client is not allowed from this address")
		return
	}

	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		deny(http.StatusBadRequest, "bad_query", "query string could not be parsed")
		return
	}
	stripParams(query, up.Inject.Query)
	params := url.Values{}
	mergeValues(params, query)

	var body []byte
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch mediaType {
	case "multipart/form-data":
		deny(http.StatusUnsupportedMediaType, "unsupported_body", "multipart bodies cannot be evaluated by policies")
		return
	case "application/x-www-form-urlencoded":
		b, err := io.ReadAll(io.LimitReader(r.Body, p.opts.MaxBodyBytes+1))
		if err != nil {
			deny(http.StatusBadRequest, "bad_body", "request body could not be read")
			return
		}
		if int64(len(b)) > p.opts.MaxBodyBytes {
			deny(http.StatusRequestEntityTooLarge, "body_too_large", "request body is too large")
			return
		}
		form, err := url.ParseQuery(string(b))
		if err != nil {
			deny(http.StatusBadRequest, "bad_body", "request body could not be parsed")
			return
		}
		stripParams(form, up.Inject.Query)
		mergeValues(params, form)
		body = []byte(form.Encode())
	}
	entry.Query = query.Encode()

	decision := evaluate(client.policies, name, Request{Method: r.Method, Path: cleanPath, Params: params})
	entry.Allowed = decision.Allowed
	entry.Reason = decision.Reason
	if !decision.Allowed {
		rec.Header().Set("X-Zandu-Decision", "deny")
		writeError(rec, http.StatusForbidden, "forbidden", decision.Reason)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), up.timeout)
	defer cancel()
	r = r.WithContext(ctx)

	creds, err := p.opts.Runtime.credentials(ctx, &up.Upstream)
	if err != nil {
		p.opts.Logger.Error("upstream credentials unavailable", "upstream", name, "error", err)
		entry.Reason = decision.Reason + "; upstream credentials unavailable"
		writeError(rec, http.StatusBadGateway, "credentials_unavailable", "upstream credentials are unavailable")
		return
	}
	for k, v := range creds.query {
		query.Set(k, v)
	}
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	rp := &httputil.ReverseProxy{
		Transport: p.opts.Transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Path = fwdPath
			pr.Out.URL.RawPath = ""
			pr.Out.URL.RawQuery = query.Encode()
			pr.SetURL(up.target)
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del(TokenHeader)
			for k, v := range creds.headers {
				pr.Out.Header.Set(k, v)
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode == http.StatusUnauthorized {
				p.opts.Runtime.invalidateToken(up.Auth)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			msg := "upstream request failed"
			if errors.Is(err, context.DeadlineExceeded) {
				msg = "upstream request timed out"
			}
			entry.Reason = decision.Reason + "; " + msg
			p.opts.Logger.Warn("upstream error", "upstream", name, "error", err)
			writeError(w, http.StatusBadGateway, "upstream_error", msg)
		},
	}
	rec.Header().Set("X-Zandu-Decision", "allow")
	rp.ServeHTTP(rec, r)
}

// splitUpstream splits "/name/rest" into "name" and "/rest".
func splitUpstream(p string) (name, rest string) {
	p = strings.TrimPrefix(p, "/")
	name, rest, _ = strings.Cut(p, "/")
	return name, "/" + rest
}

// cleanRequestPath resolves dot segments so that the evaluated path is the
// forwarded path. A trailing slash is kept for forwarding only.
func cleanRequestPath(rest string) (clean, forward string) {
	clean = path.Clean("/" + rest)
	forward = clean
	if strings.HasSuffix(rest, "/") && clean != "/" {
		forward += "/"
	}
	return clean, forward
}

// stripParams removes client-supplied parameters that collide, ignoring case,
// with injected credentials.
func stripParams(v url.Values, injected map[string]string) {
	for k := range v {
		for ik := range injected {
			if strings.EqualFold(k, ik) {
				delete(v, k)
			}
		}
	}
}

func mergeValues(dst, src url.Values) {
	for k, vs := range src {
		dst[k] = append(dst[k], vs...)
	}
}

func (p *Proxy) clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	peer = peer.Unmap()
	if !inPrefixes(p.opts.TrustedProxies, peer) {
		return peer
	}
	// Walk X-Forwarded-For from the nearest hop and return the first
	// address that is not one of our own proxies.
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(h, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return netip.Addr{}
		}
		a = a.Unmap()
		if !inPrefixes(p.opts.TrustedProxies, a) {
			return a
		}
	}
	return peer
}

func inPrefixes(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
