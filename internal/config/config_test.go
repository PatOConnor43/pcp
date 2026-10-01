package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const validConfig = `
listen: 127.0.0.1:9999
tokens:
  myapi:
    type: oauth2_client_credentials
    token_url: https://auth.example.com/oauth/token
    client_id: plain-client-id
    client_secret: '{{ secret "myapi-client-secret" }}'
    scopes: [read, write]
    params:
      audience: https://api.example.com
routes:
  - prefix: /github
    upstream: https://api.github.com
    headers:
      Authorization: 'Bearer {{ secret "github" }}'
      Accept: application/vnd.github+json
  - prefix: /myapi/
    upstream: https://api.example.com/v1/
    headers:
      Authorization: 'Bearer {{ token "myapi" }}'
`

func TestParseValid(t *testing.T) {
	cfg, err := Parse([]byte(validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9999" {
		t.Errorf("listen = %q", cfg.Listen)
	}

	ts := cfg.Tokens["myapi"]
	if ts.ClientID.Raw() != "plain-client-id" || len(ts.ClientID.Secrets()) != 0 {
		t.Errorf("client_id = %+v", ts.ClientID)
	}
	if !slices.Equal(ts.ClientSecret.Secrets(), []string{"myapi-client-secret"}) {
		t.Errorf("client_secret secrets = %v", ts.ClientSecret.Secrets())
	}
	if !slices.Equal(ts.Scopes, []string{"read", "write"}) || ts.Params["audience"] != "https://api.example.com" {
		t.Errorf("token source = %+v", ts)
	}

	gh := cfg.Routes[0]
	if !slices.Equal(gh.Headers["Authorization"].Secrets(), []string{"github"}) {
		t.Errorf("github auth secrets = %v", gh.Headers["Authorization"].Secrets())
	}
	if gh.Headers["Accept"].Raw() != "application/vnd.github+json" {
		t.Errorf("accept = %q", gh.Headers["Accept"].Raw())
	}

	my := cfg.Routes[1]
	if my.Prefix != "/myapi" {
		t.Errorf("prefix not normalized: %q", my.Prefix)
	}
	if my.UpstreamURL.String() != "https://api.example.com/v1" {
		t.Errorf("upstream not normalized: %q", my.UpstreamURL)
	}
	if !slices.Equal(my.Headers["Authorization"].Tokens(), []string{"myapi"}) {
		t.Errorf("myapi tokens = %v", my.Headers["Authorization"].Tokens())
	}

	if got, want := cfg.SecretNames(), []string{"github", "myapi-client-secret"}; !slices.Equal(got, want) {
		t.Errorf("SecretNames = %v, want %v", got, want)
	}
}

func TestParseDefaultListen(t *testing.T) {
	cfg, err := Parse([]byte("routes: [{prefix: /a, upstream: https://a.example.com}]"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != DefaultListen {
		t.Errorf("listen = %q, want %q", cfg.Listen, DefaultListen)
	}
}

func TestParseInvalid(t *testing.T) {
	const tokenSrc = `
tokens:
  t:
    type: oauth2_client_credentials
    token_url: https://auth.example.com/oauth/token
    client_id: id
    client_secret: secret
`
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{"no routes", "listen: :80", "at least one route"},
		{"unknown field", "routes: [{prefix: /a, upstream: https://a.com, nope: 1}]", "nope"},
		{"missing prefix", "routes: [{upstream: https://a.com}]", "prefix is required"},
		{"prefix without slash", "routes: [{prefix: a, upstream: https://a.com}]", "must start with /"},
		{"root prefix", "routes: [{prefix: /, upstream: https://a.com}]", "must not be /"},
		{"reserved prefix", "routes: [{prefix: /_pcp, upstream: https://a.com}]", "reserved"},
		{"reserved subprefix", "routes: [{prefix: /_pcp/x, upstream: https://a.com}]", "reserved"},
		{"invalid prefix char", "routes: [{prefix: '/a b', upstream: https://a.com}]", "invalid character"},
		{"duplicate prefix", "routes: [{prefix: /a, upstream: https://a.com}, {prefix: /a/, upstream: https://b.com}]", "duplicate prefix"},
		{"missing upstream", "routes: [{prefix: /a}]", "upstream: is required"},
		{"bad scheme", "routes: [{prefix: /a, upstream: ftp://a.com}]", "http or https"},
		{"no host", "routes: [{prefix: /a, upstream: 'https:///x'}]", "no host"},
		{"upstream query", "routes: [{prefix: /a, upstream: 'https://a.com?x=1'}]", "query"},
		{"upstream userinfo", "routes: [{prefix: /a, upstream: 'https://u:p@a.com'}]", "userinfo"},
		{"bad header name", "routes: [{prefix: /a, upstream: https://a.com, headers: {'X Bad': v}}]", "invalid header name"},
		{"template syntax", `routes: [{prefix: /a, upstream: https://a.com, headers: {A: '{{ secret "x" '}}]`, "unclosed action"},
		{"template unknown func", `routes: [{prefix: /a, upstream: https://a.com, headers: {A: '{{ env "x" }}'}}]`, "not defined"},
		{"secret non-literal", `routes: [{prefix: /a, upstream: https://a.com, headers: {A: '{{ secret .X }}'}}]`, "string literal"},
		{"secret piped", `routes: [{prefix: /a, upstream: https://a.com, headers: {A: '{{ "x" | secret }}'}}]`, "exactly one"},
		{"secret empty", `routes: [{prefix: /a, upstream: https://a.com, headers: {A: '{{ secret "" }}'}}]`, "must not be empty"},
		{"unknown token", `routes: [{prefix: /a, upstream: https://a.com, headers: {A: '{{ token "nope" }}'}}]`, `unknown token source "nope"`},
		{"token type missing", "tokens: {t: {token_url: https://a.com}}\nroutes: [{prefix: /a, upstream: https://a.com}]", "type is required"},
		{"token type unsupported", "tokens: {t: {type: magic}}\nroutes: [{prefix: /a, upstream: https://a.com}]", `unsupported type "magic"`},
		{"token missing fields", "tokens: {t: {type: oauth2_client_credentials}}\nroutes: [{prefix: /a, upstream: https://a.com}]", "client_secret is required"},
		{"token bad url", "tokens: {t: {type: oauth2_client_credentials, token_url: nope, client_id: a, client_secret: b}}\nroutes: [{prefix: /a, upstream: https://a.com}]", "token_url"},
		{"token references token", tokenSrc + `    scopes: []
  u:
    type: oauth2_client_credentials
    token_url: https://auth.example.com/oauth/token
    client_id: id
    client_secret: '{{ token "t" }}'
routes: [{prefix: /a, upstream: https://a.com}]`, "cannot reference other tokens"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseReportsMultipleErrors(t *testing.T) {
	_, err := Parse([]byte("routes: [{prefix: a, upstream: https://a.com}, {prefix: /b, upstream: ftp://b.com}]"))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"routes[0]", "routes[1]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(validConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("routes: []"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("expected error mentioning path, got %v", err)
	}
}

func TestDefaultPath(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	got, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join("/xdg", "pcp", "config.yaml") {
		t.Errorf("DefaultPath = %q", got)
	}
}

func TestTemplateRefsInControlFlow(t *testing.T) {
	tpl, err := ParseTemplate(`{{ if true }}{{ secret "a" }}{{ else }}{{ printf "%s" (secret "b") }}{{ end }}{{ token "t" }}{{ secret "a" }}`)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(tpl.Secrets(), []string{"a", "b"}) {
		t.Errorf("secrets = %v", tpl.Secrets())
	}
	if !slices.Equal(tpl.Tokens(), []string{"t"}) {
		t.Errorf("tokens = %v", tpl.Tokens())
	}
}
