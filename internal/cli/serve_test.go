package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PatOConnor43/pcp/internal/secrets"
)

// syncBuffer is a goroutine-safe buffer for capturing server logs.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type runningServer struct {
	url    string
	logs   *syncBuffer
	hangup chan os.Signal
	stop   func() int // cancels serve and returns its exit code
}

func startServe(t *testing.T, store secrets.Manager, args ...string) *runningServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	logs := &syncBuffer{}
	hangup := make(chan os.Signal, 1)
	addr := make(chan net.Addr, 1)
	done := make(chan int, 1)
	env := Env{
		Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: logs,
		Secrets: store, Context: ctx, Hangup: hangup,
		Listening: func(a net.Addr) { addr <- a },
	}
	go func() { done <- Run(append([]string{"serve", "--listen", "127.0.0.1:0"}, args...), env) }()

	select {
	case a := <-addr:
		var once sync.Once
		code := -1
		s := &runningServer{url: "http://" + a.String(), logs: logs, hangup: hangup}
		s.stop = func() int {
			once.Do(func() { cancel(); code = <-done })
			return code
		}
		t.Cleanup(func() { s.stop() })
		return s
	case code := <-done:
		cancel()
		t.Fatalf("serve exited with %d before listening:\n%s", code, logs)
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatalf("serve did not start:\n%s", logs)
	}
	return nil
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func fetch(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// echoAuth is an upstream that replies with the Authorization header it got.
func echoAuth(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Header.Get("Authorization"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestServeProxiesAndReloads(t *testing.T) {
	up := echoAuth(t)
	path := writeConfig(t, `
routes:
  - prefix: /a
    upstream: `+up.URL+`
    headers: {Authorization: '{{ secret "s" }}'}
`)
	store := secrets.Memory{"s": "v1"}
	s := startServe(t, store, "--config", path)

	if code, body := fetch(t, s.url+"/a/x"); code != 200 || body != "v1" {
		t.Fatalf("got %d %q", code, body)
	}

	// Reload picks up new secrets and routes.
	store["s"] = "v2"
	os.WriteFile(path, []byte(`
routes:
  - prefix: /a
    upstream: `+up.URL+`
    headers: {Authorization: '{{ secret "s" }}'}
  - prefix: /b
    upstream: `+up.URL+`
`), 0o600)
	s.hangup <- os.Interrupt // any signal value works
	waitFor(t, "reload", func() bool { return strings.Contains(s.logs.String(), "reloaded config") })
	if code, body := fetch(t, s.url+"/a/x"); code != 200 || body != "v2" {
		t.Errorf("after reload /a: %d %q", code, body)
	}
	if code, _ := fetch(t, s.url+"/b/x"); code != 200 {
		t.Errorf("after reload /b: %d", code)
	}

	// A broken config is rejected and the previous one keeps serving.
	os.WriteFile(path, []byte("routes: [{prefix: nope}]"), 0o600)
	s.hangup <- os.Interrupt
	waitFor(t, "reload failure", func() bool { return strings.Contains(s.logs.String(), "reload failed") })
	if code, body := fetch(t, s.url+"/a/x"); code != 200 || body != "v2" {
		t.Errorf("after failed reload: %d %q", code, body)
	}

	if code := s.stop(); code != 0 {
		t.Errorf("exit code = %d\n%s", code, s.logs)
	}
	if strings.Contains(s.logs.String(), "v1") || strings.Contains(s.logs.String(), "v2") {
		t.Errorf("secret leaked into logs:\n%s", s.logs)
	}
}

func TestServeRoutesEndpoint(t *testing.T) {
	path := writeConfig(t, "routes: [{prefix: /a, upstream: https://a.example.com}]")
	s := startServe(t, secrets.Memory{}, "--config", path)

	code, body := fetch(t, s.url+"/_pcp/routes")
	var resp struct {
		Routes []struct{ Prefix, Upstream string }
	}
	json.Unmarshal([]byte(body), &resp)
	if code != 200 || len(resp.Routes) != 1 || resp.Routes[0].Prefix != "/a" {
		t.Errorf("got %d %s", code, body)
	}
}

func TestServeStartupErrors(t *testing.T) {
	path := writeConfig(t, `routes: [{prefix: /a, upstream: https://a.com, headers: {A: '{{ secret "nope" }}'}}]`)
	r := invoke(t, Env{}, "serve", "--config", path, "--listen", "127.0.0.1:0")
	if r.code != 1 || !strings.Contains(r.stderr, "missing secrets: nope") {
		t.Errorf("missing secret: %+v", r)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	path = writeConfig(t, "routes: [{prefix: /a, upstream: https://a.com}]")
	r = invoke(t, Env{}, "serve", "--config", path, "--listen", ln.Addr().String())
	if r.code != 1 || !strings.Contains(r.stderr, "address already in use") {
		t.Errorf("port in use: %+v", r)
	}
}

func TestRoutesCommand(t *testing.T) {
	path := writeConfig(t, `
listen: 127.0.0.1:9000
routes:
  - prefix: /zeta
    upstream: https://z.example.com
  - prefix: /alpha
    upstream: https://a.example.com/v1
    headers: {Authorization: '{{ secret "never-read" }}'}
`)
	// Secrets is nil: routes must not touch the keychain.
	r := invoke(t, Env{}, "routes", "--config", path)
	if r.code != 0 {
		t.Fatalf("%+v", r)
	}
	lines := strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(lines) != 3 ||
		!lineMatches(lines[1], "http://127.0.0.1:9000/alpha", "https://a.example.com/v1") ||
		!lineMatches(lines[2], "http://127.0.0.1:9000/zeta", "https://z.example.com") {
		t.Errorf("stdout:\n%s", r.stdout)
	}

	r = invoke(t, Env{}, "routes", "--config", path, "--json")
	var out struct {
		Routes []struct{ URL, Prefix, Upstream string }
	}
	if err := json.Unmarshal([]byte(r.stdout), &out); err != nil {
		t.Fatalf("%v: %s", err, r.stdout)
	}
	if len(out.Routes) != 2 || out.Routes[0].URL != "http://127.0.0.1:9000/alpha" || out.Routes[0].Upstream != "https://a.example.com/v1" {
		t.Errorf("json: %s", r.stdout)
	}
}
