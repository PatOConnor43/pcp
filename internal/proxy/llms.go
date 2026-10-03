package proxy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/PatOConnor43/pcp/internal/config"
)

// llmsPaths serve usage docs for LLM agents. Agents know the llms.txt
// convention and often try the base URL first, so all three serve the same
// content. Route prefixes can't be "/" or llms.txt, so none are shadowed.
var llmsPaths = []string{"/", config.LLMsPath, config.ReservedPrefix + config.LLMsPath}

func (p *Proxy) serveLLMs(w http.ResponseWriter, r *http.Request) {
	if !allowGet(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, p.llmsTxt("http://"+r.Host))
}

// llmsTxt renders the docs. base is the URL the client used to reach pcp, so
// the docs stay correct when --listen overrides the configured address.
func (p *Proxy) llmsTxt(base string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `# pcp

pcp is a local proxy that adds API credentials to requests. Never ask for,
look up, or send API tokens or credential headers yourself; pcp sets them.

## Usage

Send requests to %[1]s<prefix>/<path>?<query>. They are forwarded to
<upstream>/<path>?<query> with credentials added. The method, body, and other
headers pass through unchanged.
`, base)
	if len(p.info) > 0 {
		r := p.info[0]
		fmt.Fprintf(&b, "\nFor example, `curl -s %s%s/some/path` calls `%s/some/path`.\n", base, r.Prefix, r.Upstream)
	}

	b.WriteString("\n## APIs\n\n")
	for _, r := range p.info {
		fmt.Fprintf(&b, "- %s%s → %s", base, r.Prefix, r.Upstream)
		if r.Description != "" {
			fmt.Fprintf(&b, ": %s", r.Description)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, `
## Notes

- Responses may contain absolute upstream URLs (pagination Link headers, "next"
  fields, redirects). Rewrite them to the matching local URL above before
  following them; requests sent straight to an upstream have no credentials.
- A 404 whose JSON body lists "routes" comes from pcp: the path doesn't match
  any API above. Other 404s come from the upstream.
- A 502 mentioning "token source" means pcp couldn't get a token. Report it to
  the user instead of retrying.
- After a 401, pcp discards the token it used, so retrying once is reasonable.
  Repeated 401s mean the credential lacks access; report it to the user.
- The API list is also available as JSON at %s%s.
`, base, routesPath)
	return b.String()
}
