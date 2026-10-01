// Package proxy implements pcp's credential-injecting reverse proxy.
package proxy

import (
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/PatOConnor43/pcp/internal/config"
)

// Router maps incoming request paths to configured routes.
type Router struct {
	routes []*config.Route // longest prefix first
}

func NewRouter(routes []config.Route) *Router {
	r := &Router{}
	for i := range routes {
		r.routes = append(r.routes, &routes[i])
	}
	slices.SortStableFunc(r.routes, func(a, b *config.Route) int {
		return len(b.Prefix) - len(a.Prefix)
	})
	return r
}

// Match returns the route with the longest prefix matching u's path on a
// segment boundary, and the upstream URL the request should be sent to.
func (r *Router) Match(u *url.URL) (*config.Route, *url.URL, bool) {
	// Match on the escaped path so encoded characters like %2F in the
	// remainder are forwarded intact. Prefixes contain only unreserved
	// characters, so their escaped form equals their literal form.
	p := cleanPath(u.EscapedPath())
	for _, rt := range r.routes {
		rest, ok := strings.CutPrefix(p, rt.Prefix)
		if !ok || (rest != "" && rest[0] != '/') {
			continue
		}
		return rt, target(rt.UpstreamURL, rest, u.RawQuery), true
	}
	return nil, nil, false
}

// cleanPath resolves dot segments and repeated slashes in an escaped path so a
// request can't climb above its route's upstream base path. Percent-encoded
// dots are decoded first since they are equivalent to literal dots (RFC 3986
// §2.3) and upstreams may treat them as such. Encoded slashes are left alone.
// A trailing slash is preserved.
func cleanPath(p string) string {
	p = strings.NewReplacer("%2E", ".", "%2e", ".").Replace(p)
	cleaned := path.Clean("/" + p)
	if strings.HasSuffix(p, "/") && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

// target joins the escaped remainder path onto the upstream base URL.
func target(upstream *url.URL, rest, rawQuery string) *url.URL {
	t := *upstream
	escaped := upstream.EscapedPath() + rest
	if escaped == "" {
		escaped = "/"
	}
	t.Path, _ = url.PathUnescape(escaped) // rest came from a parsed URL, so it is valid
	t.RawPath = ""
	if t.EscapedPath() != escaped {
		t.RawPath = escaped
	}
	t.RawQuery = rawQuery
	return &t
}
