package cli

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/PatOConnor43/pcp/internal/secrets"
)

type result struct {
	code           int
	stdout, stderr string
}

func invoke(t *testing.T, env Env, args ...string) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	env.Stdout, env.Stderr = &stdout, &stderr
	if env.Stdin == nil {
		env.Stdin = strings.NewReader("")
	}
	if env.Secrets == nil {
		env.Secrets = secrets.Memory{}
	}
	code := Run(args, env)
	return result{code, stdout.String(), stderr.String()}
}

func TestUsage(t *testing.T) {
	if r := invoke(t, Env{}); r.code != 2 || !strings.Contains(r.stderr, "Usage:") {
		t.Errorf("no args: %+v", r)
	}
	if r := invoke(t, Env{}, "help"); r.code != 0 || !strings.Contains(r.stdout, "Usage:") {
		t.Errorf("help: %+v", r)
	}
	if r := invoke(t, Env{}, "bogus"); r.code != 2 || !strings.Contains(r.stderr, `unknown command "bogus"`) {
		t.Errorf("bogus: %+v", r)
	}
	if r := invoke(t, Env{}, "check", "--nope"); r.code != 2 {
		t.Errorf("bad flag: %+v", r)
	}
	if r := invoke(t, Env{}, "check", "-h"); r.code != 0 || !strings.Contains(r.stderr, "-fetch") {
		t.Errorf("check -h: %+v", r)
	}
}

func TestSecretSetFromStdin(t *testing.T) {
	for _, in := range []string{"tok123", "tok123\n", "tok123\r\n"} {
		store := secrets.Memory{}
		r := invoke(t, Env{Stdin: strings.NewReader(in), Secrets: store}, "secret", "set", "gh")
		if r.code != 0 {
			t.Fatalf("input %q: %+v", in, r)
		}
		if store["gh"] != "tok123" {
			t.Errorf("input %q: stored %q", in, store["gh"])
		}
		if strings.Contains(r.stdout+r.stderr, "tok123") {
			t.Errorf("output echoes secret: %+v", r)
		}
	}
}

func TestSecretSetFromTerminal(t *testing.T) {
	store := secrets.Memory{}
	env := Env{Secrets: store, ReadPassword: func() ([]byte, error) { return []byte("typed"), nil }}
	r := invoke(t, env, "secret", "set", "gh")
	if r.code != 0 || store["gh"] != "typed" || !strings.Contains(r.stderr, "Value for gh:") {
		t.Errorf("%+v, stored %q", r, store["gh"])
	}

	env.ReadPassword = func() ([]byte, error) { return nil, errors.New("tty gone") }
	if r := invoke(t, env, "secret", "set", "x"); r.code != 1 || !strings.Contains(r.stderr, "tty gone") {
		t.Errorf("read error: %+v", r)
	}
}

func TestSecretSetInvalid(t *testing.T) {
	tests := []struct {
		name, stdin string
		args        []string
		code        int
		wantErr     string
	}{
		{"empty", "", []string{"secret", "set", "a"}, 1, "empty"},
		{"just newline", "\n", []string{"secret", "set", "a"}, 1, "empty"},
		{"multiline", "a\nb", []string{"secret", "set", "a"}, 1, "single line"},
		{"too big", strings.Repeat("x", maxSecretSize+1), []string{"secret", "set", "a"}, 1, "larger than"},
		{"control char name", "v", []string{"secret", "set", "a\tb"}, 1, "control characters"},
		{"empty name", "v", []string{"secret", "set", ""}, 1, "must not be empty"},
		{"value as arg", "", []string{"secret", "set", "a", "value"}, 2, "Usage"},
		{"no name", "", []string{"secret", "set"}, 2, "Usage"},
		{"bad subcommand", "", []string{"secret", "get", "a"}, 2, "Usage"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := secrets.Memory{}
			r := invoke(t, Env{Stdin: strings.NewReader(tt.stdin), Secrets: store}, tt.args...)
			if r.code != tt.code || !strings.Contains(r.stderr, tt.wantErr) {
				t.Errorf("got %+v, want code %d with %q", r, tt.code, tt.wantErr)
			}
			if len(store) != 0 {
				t.Errorf("stored despite error: %v", store)
			}
		})
	}
}

func TestSecretRm(t *testing.T) {
	store := secrets.Memory{"gh": "v"}
	if r := invoke(t, Env{Secrets: store}, "secret", "rm", "gh"); r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if _, ok := store["gh"]; ok {
		t.Error("secret not deleted")
	}
	if r := invoke(t, Env{Secrets: store}, "secret", "rm", "gh"); r.code != 1 || !strings.Contains(r.stderr, `secret "gh" not found`) {
		t.Errorf("rm missing: %+v", r)
	}
}

func writeConfig(t *testing.T, yaml string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func checkConfig(tokenURL string) string {
	return `
tokens:
  myapi:
    type: oauth2_client_credentials
    token_url: ` + tokenURL + `
    client_id: id
    client_secret: '{{ secret "myapi-secret" }}'
routes:
  - prefix: /github
    upstream: https://api.github.com
    headers:
      Authorization: 'Bearer {{ secret "github" }}'
  - prefix: /myapi
    upstream: https://api.example.com
    headers:
      Authorization: 'Bearer {{ token "myapi" }}'
`
}

func fakeTokenServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// lineMatches reports whether some output line matches all of the given
// whitespace-separated fields in order.
func lineMatches(out string, fields ...string) bool {
	var quoted []string
	for _, f := range fields {
		quoted = append(quoted, regexp.QuoteMeta(f))
	}
	return regexp.MustCompile(`(?m)^\s*` + strings.Join(quoted, `\s+`)).MatchString(out)
}

func TestCheckAllGood(t *testing.T) {
	srv := fakeTokenServer(t, 200, `{"access_token":"jwt-secret-value","token_type":"Bearer","expires_in":3600}`)
	path := writeConfig(t, checkConfig(srv.URL))
	store := secrets.Memory{"github": "g", "myapi-secret": "m"}

	r := invoke(t, Env{Secrets: store}, "check", "--config", path)
	if r.code != 0 {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(r.stdout, "ok (2 routes, 1 token sources)") ||
		!lineMatches(r.stdout, "github", "ok") ||
		!lineMatches(r.stdout, "myapi-secret", "ok") ||
		!lineMatches(r.stdout, "myapi", "not fetched") {
		t.Errorf("stdout:\n%s", r.stdout)
	}

	r = invoke(t, Env{Secrets: store}, "check", "--config", path, "--fetch")
	if r.code != 0 || !lineMatches(r.stdout, "myapi", "ok", "expires in") {
		t.Errorf("--fetch: %+v", r)
	}
	if strings.Contains(r.stdout+r.stderr, "jwt-secret-value") {
		t.Errorf("token printed: %+v", r)
	}
}

func TestCheckMissingSecrets(t *testing.T) {
	srv := fakeTokenServer(t, 200, `{"access_token":"x","token_type":"Bearer"}`)
	path := writeConfig(t, checkConfig(srv.URL))

	r := invoke(t, Env{Secrets: secrets.Memory{"github": "g"}}, "check", "--config", path, "--fetch")
	if r.code != 1 {
		t.Errorf("code = %d", r.code)
	}
	if !lineMatches(r.stdout, "myapi-secret", "MISSING", "run: pcp secret set myapi-secret") ||
		!lineMatches(r.stdout, "myapi", "skipped", "missing secrets: myapi-secret") {
		t.Errorf("stdout:\n%s", r.stdout)
	}
}

func TestCheckFetchFailure(t *testing.T) {
	srv := fakeTokenServer(t, 401, `{"error":"invalid_client","error_description":"bad secret m"}`)
	path := writeConfig(t, checkConfig(srv.URL))
	store := secrets.Memory{"github": "g", "myapi-secret": "m"}

	r := invoke(t, Env{Secrets: store}, "check", "--config", path, "--fetch")
	if r.code != 1 || !lineMatches(r.stdout, "myapi", "FAILED", `token source "myapi": auth server returned 401 (invalid_client)`) {
		t.Errorf("%+v", r)
	}
}

func TestCheckInvalidConfig(t *testing.T) {
	path := writeConfig(t, "routes: [{prefix: nope, upstream: https://a.com}]")
	r := invoke(t, Env{}, "check", "--config", path)
	if r.code != 1 || !strings.Contains(r.stderr, "must start with /") {
		t.Errorf("%+v", r)
	}

	r = invoke(t, Env{}, "check", "--config", filepath.Join(t.TempDir(), "missing.yaml"))
	if r.code != 1 || !strings.Contains(r.stderr, "no such file") {
		t.Errorf("missing file: %+v", r)
	}
}

func TestCheckDefaultConfigPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	os.MkdirAll(filepath.Join(dir, "pcp"), 0o700)
	os.WriteFile(filepath.Join(dir, "pcp", "config.yaml"), []byte("routes: [{prefix: /a, upstream: https://a.com}]"), 0o600)

	if r := invoke(t, Env{}, "check"); r.code != 0 || !strings.Contains(r.stdout, filepath.Join(dir, "pcp", "config.yaml")) {
		t.Errorf("%+v", r)
	}
}
