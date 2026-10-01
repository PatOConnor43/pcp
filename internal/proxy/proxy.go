package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/PatOConnor43/pcp/internal/config"
	"github.com/PatOConnor43/pcp/internal/secrets"
)

type Options struct {
	// Secrets resolves secret references. All referenced secrets are read once
	// in New and cached.
	Secrets secrets.Store
	// Transport is used for upstream requests. Defaults to http.DefaultTransport.
	Transport http.RoundTripper
	// Logger receives access and error logs. Defaults to slog.Default().
	Logger *slog.Logger
}

// Proxy is an http.Handler that forwards requests to configured upstreams with
// credential headers injected.
type Proxy struct {
	router  *Router
	headers map[*config.Route]http.Header
	rp      *httputil.ReverseProxy
	logger  *slog.Logger
}

type matchKey struct{}

type match struct {
	route  *config.Route
	target *url.URL
}

func New(cfg *config.Config, opts Options) (*Proxy, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	resolved, err := resolveSecrets(cfg.SecretNames(), opts.Secrets)
	if err != nil {
		return nil, err
	}

	p := &Proxy{
		router:  NewRouter(cfg.Routes),
		headers: map[*config.Route]http.Header{},
		logger:  opts.Logger,
	}
	for _, rt := range p.router.routes {
		h, err := renderHeaders(rt, resolved)
		if err != nil {
			return nil, fmt.Errorf("route %s: %w", rt.Prefix, err)
		}
		p.headers[rt] = h
	}

	p.rp = &httputil.ReverseProxy{
		Rewrite:       p.rewrite,
		Transport:     opts.Transport,
		FlushInterval: -1,
		ErrorHandler:  p.upstreamError,
	}
	return p, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

	route, target, ok := p.router.Match(r.URL)
	prefix := ""
	if ok {
		prefix = route.Prefix
		ctx := context.WithValue(r.Context(), matchKey{}, match{route, target})
		p.rp.ServeHTTP(rec, r.WithContext(ctx))
	} else {
		p.notFound(rec, r)
	}

	p.logger.Info("request",
		"method", r.Method,
		"path", r.URL.EscapedPath(),
		"route", prefix,
		"status", rec.status,
		"duration", time.Since(start),
	)
}

func (p *Proxy) rewrite(pr *httputil.ProxyRequest) {
	m := pr.In.Context().Value(matchKey{}).(match)
	pr.Out.URL = m.target
	pr.Out.Host = "" // use the upstream's host
	for k, v := range p.headers[m.route] {
		pr.Out.Header[k] = slices.Clone(v)
	}
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

// renderHeaders evaluates a route's header templates. Secrets are cached for
// the life of the Proxy, so the result is fixed.
func renderHeaders(rt *config.Route, resolved map[string]string) (http.Header, error) {
	funcs := template.FuncMap{
		"secret": func(name string) string { return resolved[name] },
		"token":  func(string) string { return "" }, // rejected below until token sources exist
	}
	h := http.Header{}
	for name, tpl := range rt.Headers {
		if len(tpl.Tokens()) > 0 {
			return nil, fmt.Errorf("header %s: token sources are not supported yet", name)
		}
		t, err := template.New(name).Funcs(funcs).Parse(tpl.Raw())
		if err != nil {
			return nil, fmt.Errorf("header %s: %w", name, err)
		}
		var sb strings.Builder
		if err := t.Execute(&sb, nil); err != nil {
			return nil, fmt.Errorf("header %s: %w", name, err)
		}
		v := sb.String()
		if strings.ContainsAny(v, "\r\n\x00") {
			// Don't include the value; it likely contains a secret.
			return nil, fmt.Errorf("header %s: value contains a newline or NUL", name)
		}
		h.Set(name, v)
	}
	return h, nil
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
