package proxy

import (
	"net/url"
	"testing"

	"github.com/PatOConnor43/pcp/internal/config"
)

const routerConfig = `
routes:
  - prefix: /github
    upstream: https://api.github.com
  - prefix: /git
    upstream: https://git.example.com
  - prefix: /github/enterprise
    upstream: https://ghe.example.com/api/v3/
  - prefix: /jira/
    upstream: https://example.atlassian.net/rest/api/3
  - prefix: /local
    upstream: http://localhost:9000
`

func TestRouterMatch(t *testing.T) {
	cfg, err := config.Parse([]byte(routerConfig))
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter(cfg.Routes)

	tests := []struct {
		name   string
		in     string
		prefix string // "" means no match
		want   string
	}{
		{"basic", "/github/user", "/github", "https://api.github.com/user"},
		{"query preserved", "/github/user/repos?per_page=5&sort=updated", "/github", "https://api.github.com/user/repos?per_page=5&sort=updated"},
		{"prefix only", "/github", "/github", "https://api.github.com/"},
		{"prefix with trailing slash", "/github/", "/github", "https://api.github.com/"},
		{"trailing slash preserved", "/github/user/", "/github", "https://api.github.com/user/"},
		{"segment boundary", "/gitlab/x", "", ""},
		{"shorter prefix still matches", "/git/repo", "/git", "https://git.example.com/repo"},
		{"longest prefix wins", "/github/enterprise/user", "/github/enterprise", "https://ghe.example.com/api/v3/user"},
		{"upstream base path, prefix only", "/github/enterprise", "/github/enterprise", "https://ghe.example.com/api/v3"},
		{"configured prefix trailing slash normalized", "/jira/issue/ABC-1", "/jira", "https://example.atlassian.net/rest/api/3/issue/ABC-1"},
		{"encoded slash preserved", "/git/projects/group%2Fproject/issues", "/git", "https://git.example.com/projects/group%2Fproject/issues"},
		{"encoded space", "/github/search/a%20b", "/github", "https://api.github.com/search/a%20b"},
		{"http upstream", "/local/health", "/local", "http://localhost:9000/health"},
		{"no match", "/unknown/path", "", ""},
		{"root", "/", "", ""},
		{"case sensitive", "/GitHub/user", "", ""},
		{"dot-dot within route", "/github/repos/../user", "/github", "https://api.github.com/user"},
		{"dot-dot cannot climb above base path", "/github/enterprise/../../x", "", ""},
		{"dot-dot climbing to base", "/github/enterprise/a/..", "/github/enterprise", "https://ghe.example.com/api/v3"},
		{"dot-dot crossing routes", "/github/../git/repo", "/git", "https://git.example.com/repo"},
		{"dot-dot escaping to root", "/github/..", "", ""},
		{"encoded dot-dot", "/github/enterprise/%2e%2E/%2E%2e/x", "", ""},
		{"encoded dot-dot within route", "/github/a/%2E%2E/user", "/github", "https://api.github.com/user"},
		{"single dot", "/github/./user/.", "/github", "https://api.github.com/user"},
		{"repeated slashes", "/github//user///repos", "/github", "https://api.github.com/user/repos"},
		{"trailing slash kept after clean", "/github/a/../user/", "/github", "https://api.github.com/user/"},
		{"encoded slash dot-dot is not a segment", "/git/a%2F..%2Fb", "/git", "https://git.example.com/a%2F..%2Fb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			route, got, ok := router.Match(u)
			if tt.prefix == "" {
				if ok {
					t.Fatalf("expected no match, got %s -> %s", route.Prefix, got)
				}
				return
			}
			if !ok {
				t.Fatalf("expected match on %s, got none", tt.prefix)
			}
			if route.Prefix != tt.prefix {
				t.Errorf("prefix = %s, want %s", route.Prefix, tt.prefix)
			}
			if got.String() != tt.want {
				t.Errorf("target = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRouterMatchDoesNotMutateUpstream(t *testing.T) {
	cfg, err := config.Parse([]byte(routerConfig))
	if err != nil {
		t.Fatal(err)
	}
	router := NewRouter(cfg.Routes)
	u, _ := url.Parse("/github/user?x=1")
	route, _, _ := router.Match(u)
	if got := route.UpstreamURL.String(); got != "https://api.github.com" {
		t.Errorf("upstream mutated: %s", got)
	}
}
