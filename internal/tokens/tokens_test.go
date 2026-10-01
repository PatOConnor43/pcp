package tokens

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2/clientcredentials"

	"github.com/PatOConnor43/pcp/internal/config"
)

// authServer is a fake OAuth2 token endpoint. Each successful fetch returns
// a distinct token "tok-N".
type authServer struct {
	*httptest.Server
	fetches   atomic.Int32
	expiresIn int // 0 omits expires_in
	delay     time.Duration

	mu      sync.Mutex
	lastReq *http.Request // form already parsed
}

func newAuthServer(t *testing.T, expiresIn int) *authServer {
	t.Helper()
	a := &authServer{expiresIn: expiresIn}
	a.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		a.mu.Lock()
		a.lastReq = r
		a.mu.Unlock()
		time.Sleep(a.delay)
		n := a.fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		exp := ""
		if a.expiresIn > 0 {
			exp = fmt.Sprintf(`,"expires_in":%d`, a.expiresIn)
		}
		fmt.Fprintf(w, `{"access_token":"tok-%d","token_type":"Bearer"%s}`, n, exp)
	}))
	t.Cleanup(a.Close)
	return a
}

func (a *authServer) source() *ClientCredentials {
	return NewClientCredentials("test", clientcredentials.Config{
		ClientID:     "id",
		ClientSecret: "shh",
		TokenURL:     a.URL + "/oauth/token",
	}, nil)
}

func mustToken(t *testing.T, s Source) string {
	t.Helper()
	tok, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestTokenCached(t *testing.T) {
	a := newAuthServer(t, 3600)
	s := a.source()
	if got := mustToken(t, s); got != "tok-1" {
		t.Errorf("first token = %q", got)
	}
	if got := mustToken(t, s); got != "tok-1" {
		t.Errorf("second token = %q, want cached tok-1", got)
	}
	if n := a.fetches.Load(); n != 1 {
		t.Errorf("fetches = %d, want 1", n)
	}
}

func TestTokenWithoutExpiryCached(t *testing.T) {
	a := newAuthServer(t, 0)
	s := a.source()
	mustToken(t, s)
	mustToken(t, s)
	if n := a.fetches.Load(); n != 1 {
		t.Errorf("fetches = %d, want 1", n)
	}
}

func TestTokenRefreshedNearExpiry(t *testing.T) {
	a := newAuthServer(t, int(refreshBefore/time.Second)-1)
	s := a.source()
	if got := mustToken(t, s); got != "tok-1" {
		t.Errorf("first token = %q", got)
	}
	if got := mustToken(t, s); got != "tok-2" {
		t.Errorf("second token = %q, want refreshed tok-2", got)
	}
}

func TestTokenConcurrentFetchesShared(t *testing.T) {
	a := newAuthServer(t, 3600)
	a.delay = 50 * time.Millisecond
	s := a.source()

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if got := mustToken(t, s); got != "tok-1" {
				t.Errorf("token = %q", got)
			}
		})
	}
	wg.Wait()
	if n := a.fetches.Load(); n != 1 {
		t.Errorf("fetches = %d, want 1", n)
	}
}

func TestInvalidate(t *testing.T) {
	a := newAuthServer(t, 3600)
	s := a.source()
	tok1 := mustToken(t, s)

	s.Invalidate("some-stale-token")
	if got := mustToken(t, s); got != tok1 {
		t.Errorf("stale invalidate dropped current token: got %q", got)
	}

	s.Invalidate(tok1)
	if got := mustToken(t, s); got != "tok-2" {
		t.Errorf("after invalidate = %q, want tok-2", got)
	}
}

func TestTokenRequest(t *testing.T) {
	a := newAuthServer(t, 3600)
	sources, err := NewSources(map[string]config.TokenSource{
		"myapi": {
			Type:         config.TypeOAuth2ClientCredentials,
			TokenURL:     a.URL + "/oauth/token",
			ClientID:     mustTemplate(t, "my-id"),
			ClientSecret: mustTemplate(t, `{{ secret "cs" }}`),
			Scopes:       []string{"read", "write"},
			Params:       map[string]string{"audience": "https://api.example.com"},
		},
	}, func(name string) (string, error) {
		if name != "cs" {
			return "", fmt.Errorf("unexpected secret %q", name)
		}
		return "my-secret", nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	mustToken(t, sources["myapi"])

	a.mu.Lock()
	r := a.lastReq
	a.mu.Unlock()
	if r.Method != http.MethodPost || r.URL.Path != "/oauth/token" {
		t.Errorf("request = %s %s", r.Method, r.URL.Path)
	}
	for k, want := range map[string]string{
		"grant_type": "client_credentials",
		"scope":      "read write",
		"audience":   "https://api.example.com",
	} {
		if got := r.PostForm.Get(k); got != want {
			t.Errorf("form %s = %q, want %q", k, got, want)
		}
	}
	id, secret, ok := r.BasicAuth()
	if !ok || id != "my-id" || secret != "my-secret" {
		t.Errorf("basic auth = %q %q %v", id, secret, ok)
	}
}

func TestNewSourcesSecretError(t *testing.T) {
	_, err := NewSources(map[string]config.TokenSource{
		"x": {
			Type:         config.TypeOAuth2ClientCredentials,
			TokenURL:     "https://a.example.com/token",
			ClientID:     mustTemplate(t, "id"),
			ClientSecret: mustTemplate(t, `{{ secret "missing" }}`),
		},
	}, func(name string) (string, error) { return "", errors.New("no such secret") }, nil)
	if err == nil || !strings.Contains(err.Error(), `token source "x": client_secret`) {
		t.Fatalf("err = %v", err)
	}
}

func TestFetchErrorFromAuthServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_client","error_description":"bad secret shh"}`)
	}))
	defer srv.Close()
	s := NewClientCredentials("myapi", clientcredentials.Config{
		ClientID: "id", ClientSecret: "shh", TokenURL: srv.URL,
	}, nil)

	_, err := s.Token(context.Background())
	fe, ok := errors.AsType[*FetchError](err)
	if !ok {
		t.Fatalf("err = %T %v, want *FetchError", err, err)
	}
	if fe.Status != http.StatusUnauthorized || fe.Code != "invalid_client" {
		t.Errorf("FetchError = %+v", fe)
	}
	if want := `token source "myapi": auth server returned 401 (invalid_client)`; err.Error() != want {
		t.Errorf("message = %q, want %q", err, want)
	}
	if strings.Contains(err.Error(), "shh") {
		t.Errorf("error leaks auth server body: %v", err)
	}
}

func TestFetchErrorUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	s := NewClientCredentials("myapi", clientcredentials.Config{
		ClientID: "id", ClientSecret: "shh", TokenURL: url,
	}, nil)

	_, err := s.Token(context.Background())
	fe, ok := errors.AsType[*FetchError](err)
	if !ok || fe.Status != 0 || fe.Err == nil {
		t.Fatalf("err = %#v", err)
	}
	if strings.Contains(err.Error(), "shh") {
		t.Errorf("error leaks secret: %v", err)
	}
}

func mustTemplate(t *testing.T, s string) config.Template {
	t.Helper()
	tpl, err := config.ParseTemplate(s)
	if err != nil {
		t.Fatal(err)
	}
	return tpl
}
