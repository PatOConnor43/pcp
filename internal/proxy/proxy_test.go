package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PatOConnor43/pcp/internal/config"
	"github.com/PatOConnor43/pcp/internal/secrets"
)

const testSecret = "s3cr3t-value"

// received is what the fake upstream saw.
type received struct {
	method string
	uri    string
	host   string
	header http.Header
	body   string
}

// newUpstream starts a fake upstream that records requests and replies 201
// with a fixed body and header.
func newUpstream(t *testing.T) (*httptest.Server, chan received) {
	t.Helper()
	ch := make(chan received, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ch <- received{r.Method, r.RequestURI, r.Host, r.Header.Clone(), string(body)}
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "upstream body")
	}))
	t.Cleanup(srv.Close)
	return srv, ch
}

// newProxy starts pcp in front of the given config. The returned logs func
// shuts the server down (waiting for in-flight handlers, which log after
// responding) and returns everything logged.
func newProxy(t *testing.T, yaml string, store secrets.Store) (*httptest.Server, func() string) {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	p, err := New(cfg, Options{
		Secrets: store,
		Logger:  slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return srv, func() string {
		srv.Close()
		return logs.String()
	}
}

func routeYAML(upstream string) string {
	return `
routes:
  - prefix: /api
    upstream: ` + upstream + `/base
    headers:
      Authorization: 'Bearer {{ secret "tok" }}'
      x-api-key: '{{ secret "key" }}'
      Accept: application/json
`
}

func TestProxyInjectsHeadersAndRewrites(t *testing.T) {
	up, got := newUpstream(t)
	px, logs := newProxy(t, routeYAML(up.URL), secrets.Memory{"tok": testSecret, "key": "k-123"})

	req, _ := http.NewRequest(http.MethodPost, px.URL+"/api/items/1?verbose=true&x=%20y", strings.NewReader(`{"a":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client", "kept")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	r := <-got
	if r.method != http.MethodPost || r.uri != "/base/items/1?verbose=true&x=%20y" {
		t.Errorf("upstream got %s %s", r.method, r.uri)
	}
	if r.host != strings.TrimPrefix(up.URL, "http://") {
		t.Errorf("Host = %q, want upstream host", r.host)
	}
	for k, want := range map[string]string{
		"Authorization": "Bearer " + testSecret,
		"X-Api-Key":     "k-123",
		"Accept":        "application/json",
		"Content-Type":  "application/json",
		"X-Client":      "kept",
	} {
		if v := r.header.Get(k); v != want {
			t.Errorf("upstream header %s = %q, want %q", k, v, want)
		}
	}
	if r.header.Get("X-Forwarded-For") != "" || r.header.Get("X-Forwarded-Host") != "" {
		t.Errorf("unexpected forwarding headers: %v", r.header)
	}
	if r.body != `{"a":1}` {
		t.Errorf("upstream body = %q", r.body)
	}

	if resp.StatusCode != http.StatusCreated || resp.Header.Get("X-Upstream") != "yes" || string(body) != "upstream body" {
		t.Errorf("client got %d %v %q", resp.StatusCode, resp.Header, body)
	}

	l := logs()
	if strings.Contains(l, testSecret) {
		t.Errorf("secret leaked into logs: %s", l)
	}
	if !strings.Contains(l, "route=/api") || !strings.Contains(l, "status=201") {
		t.Errorf("access log missing fields: %s", l)
	}
}

func TestProxyOverwritesClientHeaders(t *testing.T) {
	up, got := newUpstream(t)
	px, _ := newProxy(t, routeYAML(up.URL), secrets.Memory{"tok": testSecret, "key": "k-123"})

	req, _ := http.NewRequest(http.MethodGet, px.URL+"/api/x", nil)
	req.Header.Add("Authorization", "Bearer client-supplied")
	req.Header.Add("Authorization", "Basic another")
	req.Header.Set("X-API-KEY", "client-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	r := <-got
	if v := r.header.Values("Authorization"); len(v) != 1 || v[0] != "Bearer "+testSecret {
		t.Errorf("Authorization = %v", v)
	}
	if v := r.header.Values("X-Api-Key"); len(v) != 1 || v[0] != "k-123" {
		t.Errorf("X-Api-Key = %v", v)
	}
}

func TestProxyNotFound(t *testing.T) {
	up, got := newUpstream(t)
	px, logs := newProxy(t, routeYAML(up.URL), secrets.Memory{"tok": testSecret, "key": "k"})

	for _, path := range []string{"/nope", "/apix", "/api/../etc", "/_pcp/other"} {
		resp, err := http.Get(px.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Error  string      `json:"error"`
			Help   string      `json:"help"`
			Routes []RouteInfo `json:"routes"`
		}
		err = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Content-Type") != "application/json" {
			t.Errorf("%s: got %d %s", path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		if !strings.Contains(body.Help, "/llms.txt") {
			t.Errorf("%s: help = %q", path, body.Help)
		}
		if len(body.Routes) != 1 || body.Routes[0] != (RouteInfo{"/api", up.URL + "/base"}) {
			t.Errorf("%s: routes = %+v", path, body.Routes)
		}
	}
	select {
	case r := <-got:
		t.Errorf("upstream should not be called, got %s", r.uri)
	default:
	}
	if l := logs(); !strings.Contains(l, "status=404") {
		t.Errorf("access log missing 404: %s", l)
	}
}

func TestProxyUpstreamUnavailable(t *testing.T) {
	up, _ := newUpstream(t)
	url := up.URL
	up.Close()
	px, logs := newProxy(t, routeYAML(url), secrets.Memory{"tok": testSecret, "key": "k"})

	resp, err := http.Get(px.URL + "/api/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct{ Error string }
	json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body.Error, "failed") {
		t.Errorf("got %d %+v", resp.StatusCode, body)
	}
	if l := logs(); strings.Contains(l, testSecret) {
		t.Errorf("secret leaked into logs: %s", l)
	}
}

func TestProxyStreamsResponses(t *testing.T) {
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "data: second\n\n")
	}))
	defer up.Close()
	defer close(release)
	px, _ := newProxy(t, "routes: [{prefix: /s, upstream: "+up.URL+"}]", nil)

	// Closed by the defer below; bodyclose loses track because the body is
	// read in a goroutine.
	resp, err := http.Get(px.URL + "/s/events") //nolint:bodyclose
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	line := make(chan string, 1)
	go func() {
		l, _ := bufio.NewReader(resp.Body).ReadString('\n')
		line <- l
	}()
	select {
	case l := <-line:
		if l != "data: first\n" {
			t.Errorf("first line = %q", l)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first event not flushed before upstream finished")
	}
}

func TestProxyTLSUpstream(t *testing.T) {
	gotAuth := make(chan string, 1)
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth <- r.Header.Get("Authorization")
	}))
	defer up.Close()

	cfg, err := config.Parse([]byte(`routes: [{prefix: /t, upstream: ` + up.URL + `, headers: {Authorization: '{{ secret "a" }}'}}]`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, Options{Secrets: secrets.Memory{"a": "x"}, Transport: up.Client().Transport, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/t/ok", nil))
	if auth := <-gotAuth; rec.Code != http.StatusOK || auth != "x" {
		t.Errorf("got %d, auth %q", rec.Code, auth)
	}
}

func TestNewErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		store   secrets.Store
		wantErr string
		notErr  string
	}{
		{
			name:    "missing secrets listed together",
			yaml:    `routes: [{prefix: /a, upstream: https://a.com, headers: {A: '{{ secret "x" }}', B: '{{ secret "y" }}{{ secret "z" }}'}}]`,
			store:   secrets.Memory{"y": "ok"},
			wantErr: "missing secrets: x, z",
		},
		{
			name:    "nil store with references",
			yaml:    `routes: [{prefix: /a, upstream: https://a.com, headers: {A: '{{ secret "x" }}'}}]`,
			wantErr: "missing secrets: x",
		},
		{
			name:    "newline in secret value",
			yaml:    `routes: [{prefix: /a, upstream: https://a.com, headers: {A: '{{ secret "x" }}'}}]`,
			store:   secrets.Memory{"x": "line1\nline2"},
			wantErr: "header A: value contains a newline",
			notErr:  "line1",
		},
		{
			name: "missing token source secret",
			yaml: `
tokens: {t: {type: oauth2_client_credentials, token_url: https://a.com/token, client_id: a, client_secret: '{{ secret "cs" }}'}}
routes: [{prefix: /a, upstream: https://a.com, headers: {A: '{{ token "t" }}'}}]`,
			wantErr: "missing secrets: cs",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.Parse([]byte(tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			_, err = New(cfg, Options{Secrets: tt.store})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
			if tt.notErr != "" && strings.Contains(err.Error(), tt.notErr) {
				t.Errorf("error leaks secret value: %v", err)
			}
		})
	}
}

func TestProxyRoutesEndpoint(t *testing.T) {
	px, _ := newProxy(t, `
routes:
  - prefix: /zeta
    upstream: https://z.example.com
  - prefix: /alpha
    upstream: https://a.example.com/v1
    headers: {Authorization: '{{ secret "s" }}'}
`, secrets.Memory{"s": testSecret})

	resp, err := http.Get(px.URL + "/_pcp/routes")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var body struct {
		Usage  string
		Routes []RouteInfo
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	want := []RouteInfo{{"/alpha", "https://a.example.com/v1"}, {"/zeta", "https://z.example.com"}}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "<prefix>") || !slices.Equal(body.Routes, want) {
		t.Errorf("got %d %s", resp.StatusCode, raw)
	}
	if strings.Contains(string(raw), testSecret) {
		t.Errorf("routes endpoint leaks secret: %s", raw)
	}

	resp, err = http.Post(px.URL+"/_pcp/routes", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "GET, HEAD" {
		t.Errorf("POST: %d %v", resp.StatusCode, resp.Header)
	}
}

func TestProxyLLMsTxt(t *testing.T) {
	px, _ := newProxy(t, `
routes:
  - prefix: /zeta
    upstream: https://z.example.com
  - prefix: /alpha
    upstream: https://a.example.com/v1
    headers: {Authorization: '{{ secret "s" }}'}
`, secrets.Memory{"s": testSecret})

	for _, path := range []string{"/", "/llms.txt", "/_pcp/llms.txt", "/_pcp/../llms.txt"} {
		resp, err := http.Get(px.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		body := string(raw)
		if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
			t.Errorf("%s: got %d %s", path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		for _, want := range []string{
			"- " + px.URL + "/alpha → https://a.example.com/v1\n- " + px.URL + "/zeta → https://z.example.com\n",
			"`curl -s " + px.URL + "/alpha/some/path` calls `https://a.example.com/v1/some/path`",
			px.URL + "/_pcp/routes",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: missing %q in:\n%s", path, want, body)
			}
		}
		if strings.Contains(body, testSecret) || strings.Contains(body, "Authorization") {
			t.Errorf("%s: leaks credential details:\n%s", path, body)
		}
	}

	resp, err := http.Post(px.URL+"/llms.txt", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", resp.StatusCode)
	}
}
