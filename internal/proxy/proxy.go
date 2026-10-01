package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/PatOConnor43/pcp/internal/config"
	"github.com/PatOConnor43/pcp/internal/secrets"
	"github.com/PatOConnor43/pcp/internal/tokens"
)

type Options struct {
	// Secrets resolves secret references. All referenced secrets are read once
	// in New and cached.
	Secrets secrets.Store
	// Transport is used for upstream and token requests. Defaults to
	// http.DefaultTransport.
	Transport http.RoundTripper
	// Logger receives access and error logs. Defaults to slog.Default().
	Logger *slog.Logger
}

// Proxy is an http.Handler that forwards requests to configured upstreams with
// credential headers injected.
type Proxy struct {
	router  *Router
	routes  map[*config.Route]*routeHeaders
	sources map[string]tokens.Source
	rp      *httputil.ReverseProxy
	logger  *slog.Logger
}

// routeHeaders holds a route's credential headers. Headers that only use
// secrets are rendered once in New; headers that use tokens are rendered per
// request since tokens expire.
type routeHeaders struct {
	static  http.Header
	dynamic map[string]*template.Template // header name -> template
	tokens  []string                      // token sources used by dynamic
}

type matchKey struct{}

type match struct {
	route  *config.Route
	target *url.URL
	header http.Header       // credential headers to set
	tokens map[string]string // token values used, by source name
}

// tokenFetchTimeout bounds a single token request.
const tokenFetchTimeout = 30 * time.Second

func New(cfg *config.Config, opts Options) (*Proxy, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	resolved, err := resolveSecrets(cfg.SecretNames(), opts.Secrets)
	if err != nil {
		return nil, err
	}

	secret := func(name string) (string, error) {
		v, ok := resolved[name]
		if !ok {
			return "", fmt.Errorf("secret %q not loaded", name)
		}
		return v, nil
	}
	sources, err := tokens.NewSources(cfg.Tokens, secret, &http.Client{
		Transport: opts.Transport,
		Timeout:   tokenFetchTimeout,
	})
	if err != nil {
		return nil, err
	}

	p := &Proxy{
		router:  NewRouter(cfg.Routes),
		routes:  map[*config.Route]*routeHeaders{},
		sources: sources,
		logger:  opts.Logger,
	}
	for _, rt := range p.router.routes {
		h, err := compileHeaders(rt, secret)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", rt.Prefix, err)
		}
		p.routes[rt] = h
	}

	p.rp = &httputil.ReverseProxy{
		Rewrite:        p.rewrite,
		ModifyResponse: p.modifyResponse,
		Transport:      opts.Transport,
		FlushInterval:  -1,
		ErrorHandler:   p.upstreamError,
	}
	return p, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

	route, target, ok := p.router.Match(r.URL)
	prefix := ""
	defer func() {
		p.logger.Info("request",
			"method", r.Method,
			"path", r.URL.EscapedPath(),
			"route", prefix,
			"status", rec.status,
			"duration", time.Since(start),
		)
	}()
	if !ok {
		p.notFound(rec, r)
		return
	}
	prefix = route.Prefix

	header, toks, err := p.credentialHeaders(r.Context(), route)
	if errors.Is(err, context.Canceled) {
		rec.WriteHeader(499) // client went away during a token fetch
		return
	}
	if err != nil {
		p.logger.Error("credential headers failed", "route", prefix, "err", err)
		writeJSON(rec, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return
	}
	ctx := context.WithValue(r.Context(), matchKey{}, match{route, target, header, toks})
	p.rp.ServeHTTP(rec, r.WithContext(ctx))
}

// credentialHeaders returns the headers to inject for route, fetching any
// tokens it needs. Errors are safe to return to the client.
func (p *Proxy) credentialHeaders(ctx context.Context, route *config.Route) (http.Header, map[string]string, error) {
	rh := p.routes[route]
	if len(rh.tokens) == 0 {
		return rh.static, nil, nil
	}
	toks := map[string]string{}
	for _, name := range rh.tokens {
		v, err := p.sources[name].Token(ctx)
		if err != nil {
			return nil, nil, err
		}
		toks[name] = v
	}
	funcs := template.FuncMap{"token": func(name string) string { return toks[name] }}
	h := rh.static.Clone()
	for name, tpl := range rh.dynamic {
		t, err := tpl.Clone()
		if err != nil {
			return nil, nil, fmt.Errorf("header %s: %w", name, err)
		}
		v, err := execute(t.Funcs(funcs))
		if err != nil {
			return nil, nil, fmt.Errorf("header %s: %w", name, err)
		}
		if err := checkHeaderValue(v); err != nil {
			return nil, nil, fmt.Errorf("header %s: %w", name, err)
		}
		h.Set(name, v)
	}
	return h, toks, nil
}

func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	m := pr.In.Context().Value(matchKey{}).(match)
	pr.Out.URL = m.target
	pr.Out.Host = "" // use the upstream's host
	for k, v := range m.header {
		pr.Out.Header[k] = slices.Clone(v)
	}
}

// modifyResponse drops cached tokens the upstream rejected so the next
// request fetches fresh ones. The rejected response is still returned as-is.
func (p *Proxy) modifyResponse(resp *http.Response) error {
	if resp.StatusCode != http.StatusUnauthorized {
		return nil
	}
	m := resp.Request.Context().Value(matchKey{}).(match)
	for name, v := range m.tokens {
		p.sources[name].Invalidate(v)
		p.logger.Info("upstream returned 401; invalidated token", "route", m.route.Prefix, "token_source", name)
	}
	return nil
}

func (p *Proxy) upstreamError(w http.ResponseWriter, r *http.Request, err error) {
	m := r.Context().Value(matchKey{}).(match)
	if errors.Is(err, context.Canceled) {
		// Client went away; there's no one to respond to.
		p.logger.Debug("client canceled request", "route", m.route.Prefix)
		w.WriteHeader(499)
		return
	}
	p.logger.Error("upstream request failed", "route", m.route.Prefix, "upstream", m.route.UpstreamURL.Host, "err", err)
	writeJSON(w, http.StatusBadGateway, map[string]any{
		"error": fmt.Sprintf("upstream request to %s failed", m.route.UpstreamURL.Host),
	})
}

type routeInfo struct {
	Prefix   string `json:"prefix"`
	Upstream string `json:"upstream"`
}

func (p *Proxy) notFound(w http.ResponseWriter, r *http.Request) {
	routes := make([]routeInfo, 0, len(p.router.routes))
	for _, rt := range p.router.routes {
		routes = append(routes, routeInfo{rt.Prefix, rt.UpstreamURL.String()})
	}
	writeJSON(w, http.StatusNotFound, map[string]any{
		"error":  fmt.Sprintf("no route matches %s", r.URL.EscapedPath()),
		"routes": routes,
	})
}

func resolveSecrets(names []string, store secrets.Store) (map[string]string, error) {
	resolved := map[string]string{}
	var missing []string
	for _, name := range names {
		if store == nil {
			missing = append(missing, name)
			continue
		}
		v, err := store.Get(name)
		if errors.Is(err, secrets.ErrNotFound) {
			missing = append(missing, name)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading secret %q: %w", name, err)
		}
		resolved[name] = v
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing secrets: %s", strings.Join(missing, ", "))
	}
	return resolved, nil
}

// compileHeaders prepares a route's header templates. Secrets are cached for
// the life of the Proxy, so headers without token references are rendered
// immediately.
func compileHeaders(rt *config.Route, secret func(string) (string, error)) (*routeHeaders, error) {
	rh := &routeHeaders{static: http.Header{}, dynamic: map[string]*template.Template{}}
	for _, name := range slices.Sorted(maps.Keys(rt.Headers)) {
		tpl := rt.Headers[name]
		t, err := tpl.Compile(template.FuncMap{"secret": secret})
		if err != nil {
			return nil, fmt.Errorf("header %s: %w", name, err)
		}
		if len(tpl.Tokens()) > 0 {
			rh.dynamic[name] = t
			for _, tok := range tpl.Tokens() {
				if !slices.Contains(rh.tokens, tok) {
					rh.tokens = append(rh.tokens, tok)
				}
			}
			continue
		}
		v, err := execute(t)
		if err != nil {
			return nil, fmt.Errorf("header %s: %w", name, err)
		}
		if err := checkHeaderValue(v); err != nil {
			return nil, fmt.Errorf("header %s: %w", name, err)
		}
		rh.static.Set(name, v)
	}
	return rh, nil
}

func execute(t *template.Template) (string, error) {
	var sb strings.Builder
	if err := t.Execute(&sb, nil); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// checkHeaderValue rejects values that can't be sent as a header. The value
// is not included in the error since it likely contains a credential.
func checkHeaderValue(v string) error {
	if strings.ContainsAny(v, "\r\n\x00") {
		return errors.New("value contains a newline or NUL")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// statusRecorder captures the response status for access logging. Unwrap lets
// http.ResponseController reach the underlying writer for flushing.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader && code >= 200 { // ignore 1xx informational responses
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
