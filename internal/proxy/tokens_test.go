package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/PatOConnor43/pcp/internal/secrets"
)

// fakeAuth is an OAuth2 token endpoint issuing "jwt-N". If fail is set it
// rejects requests with 401 and a body echoing the client secret.
type fakeAuth struct {
	*httptest.Server
	fetches atomic.Int32
	fail    atomic.Bool
}

func newFakeAuth(t *testing.T) *fakeAuth {
	t.Helper()
	a := &fakeAuth{}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if a.fail.Load() {
			_, secret, _ := r.BasicAuth()
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"error":"invalid_client","error_description":"bad secret %s"}`, secret)
			return
		}
		fmt.Fprintf(w, `{"access_token":"jwt-%d","token_type":"Bearer","expires_in":3600}`, a.fetches.Add(1))
	}))
	t.Cleanup(a.Close)
	return a
}

// authUpstream records the Authorization header of each request and replies
// with the given status.
type authUpstream struct {
	*httptest.Server
	auths  chan string
	status atomic.Int32
}

func newAuthUpstream(t *testing.T) *authUpstream {
	t.Helper()
	u := &authUpstream{auths: make(chan string, 10)}
	u.status.Store(http.StatusOK)
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.auths <- r.Header.Get("Authorization")
		w.WriteHeader(int(u.status.Load()))
		io.WriteString(w, "upstream says hi")
	}))
	t.Cleanup(u.Close)
	return u
}

func tokenYAML(auth, upstream string) string {
	return `
tokens:
  myapi:
    type: oauth2_client_credentials
    token_url: ` + auth + `/oauth/token
    client_id: my-client
    client_secret: '{{ secret "myapi-secret" }}'
routes:
  - prefix: /myapi
    upstream: ` + upstream + `
    headers:
      Authorization: 'Bearer {{ token "myapi" }}'
      X-Static: '{{ secret "static" }}'
`
}

var tokenSecrets = secrets.Memory{"myapi-secret": "client-s3cret", "static": "static-value"}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestTokenInjectedAndCached(t *testing.T) {
	auth := newFakeAuth(t)
	up := newAuthUpstream(t)
	px, _ := newProxy(t, tokenYAML(auth.URL, up.URL), tokenSecrets)

	if auth.fetches.Load() != 0 {
		t.Fatal("token fetched at startup; want lazy fetch")
	}
	for i := range 3 {
		if code, _ := get(t, px.URL+"/myapi/x"); code != http.StatusOK {
			t.Fatalf("request %d: status %d", i, code)
		}
		if got := <-up.auths; got != "Bearer jwt-1" {
			t.Errorf("request %d: Authorization = %q", i, got)
		}
	}
	if n := auth.fetches.Load(); n != 1 {
		t.Errorf("token fetches = %d, want 1", n)
	}
}

func TestTokenRouteKeepsStaticHeaders(t *testing.T) {
	auth := newFakeAuth(t)
	static := make(chan string, 1)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		static <- r.Header.Get("X-Static")
	}))
	defer up.Close()
	px, _ := newProxy(t, tokenYAML(auth.URL, up.URL), tokenSecrets)

	get(t, px.URL+"/myapi/x")
	if got := <-static; got != "static-value" {
		t.Errorf("X-Static = %q", got)
	}
}

func TestUpstream401InvalidatesToken(t *testing.T) {
	auth := newFakeAuth(t)
	up := newAuthUpstream(t)
	px, logs := newProxy(t, tokenYAML(auth.URL, up.URL), tokenSecrets)

	get(t, px.URL+"/myapi/x")
	<-up.auths

	// Upstream rejects the token: the 401 is passed through unchanged,
	// without an automatic retry.
	up.status.Store(http.StatusUnauthorized)
	code, body := get(t, px.URL+"/myapi/x")
	if code != http.StatusUnauthorized || body != "upstream says hi" {
		t.Errorf("got %d %q, want upstream's 401", code, body)
	}
	if got := <-up.auths; got != "Bearer jwt-1" {
		t.Errorf("Authorization = %q", got)
	}
	if n := auth.fetches.Load(); n != 1 {
		t.Errorf("token fetches = %d, want 1 (no retry)", n)
	}

	// The next request uses a fresh token.
	up.status.Store(http.StatusOK)
	get(t, px.URL+"/myapi/x")
	if got := <-up.auths; got != "Bearer jwt-2" {
		t.Errorf("Authorization after 401 = %q, want refreshed token", got)
	}

	if l := logs(); !strings.Contains(l, "invalidated token") || strings.Contains(l, "jwt-") {
		t.Errorf("logs should note invalidation without the token: %s", l)
	}
}

func TestTokenFetchFailure(t *testing.T) {
	auth := newFakeAuth(t)
	auth.fail.Store(true)
	up := newAuthUpstream(t)
	px, logs := newProxy(t, tokenYAML(auth.URL, up.URL), tokenSecrets)

	code, body := get(t, px.URL+"/myapi/x")
	if code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", code)
	}
	var resp struct{ Error string }
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("body %q: %v", body, err)
	}
	if want := `token source "myapi": auth server returned 401 (invalid_client)`; resp.Error != want {
		t.Errorf("error = %q, want %q", resp.Error, want)
	}
	select {
	case a := <-up.auths:
		t.Errorf("upstream called with %q", a)
	default:
	}

	// Recovers once the auth server does.
	auth.fail.Store(false)
	if code, _ := get(t, px.URL+"/myapi/x"); code != http.StatusOK {
		t.Errorf("status after recovery = %d", code)
	}
	<-up.auths

	if l := logs(); strings.Contains(l, "client-s3cret") || strings.Contains(body, "client-s3cret") {
		t.Errorf("client secret leaked:\nbody: %s\nlogs: %s", body, l)
	}
}

func TestTokenFailureIsolatedToRoute(t *testing.T) {
	auth := newFakeAuth(t)
	auth.fail.Store(true)
	up := newAuthUpstream(t)
	yaml := tokenYAML(auth.URL, up.URL) + `
  - prefix: /plain
    upstream: ` + up.URL + `
`
	px, _ := newProxy(t, yaml, tokenSecrets)

	if code, _ := get(t, px.URL+"/plain/x"); code != http.StatusOK {
		t.Errorf("secret-only route status = %d", code)
	}
}
