# pcp Implementation Plan

pcp is a local **reverse proxy**. Clients (LLMs) call plain HTTP on localhost with a
route prefix; pcp rewrites the request to the configured upstream over HTTPS and
injects credentials. No MITM, no CA certs.

```
curl localhost:8080/github/user/repos?per_page=5
  → GET https://api.github.com/user/repos?per_page=5
    Authorization: Bearer <from keychain>
```

## Config

Default location: `~/.config/pcp/config.yaml` (YAML via `goccy/go-yaml`).

```yaml
listen: 127.0.0.1:8080

tokens:
  myapi:
    type: oauth2_client_credentials
    token_url: https://auth.example.com/oauth/token
    client_id: "{{ secret \"myapi-client-id\" }}"
    client_secret: "{{ secret \"myapi-client-secret\" }}"
    scopes: [read, write]          # optional
    params:                        # optional extra form fields
      audience: https://api.example.com

routes:
  - prefix: /github
    upstream: https://api.github.com
    headers:
      Authorization: "Bearer {{ secret \"github\" }}"
      Accept: application/vnd.github+json
  - prefix: /myapi
    upstream: https://api.example.com
    headers:
      Authorization: "Bearer {{ token \"myapi\" }}"
```

- Header values (and token source credential fields) are Go templates with two
  functions: `secret "<name>"` (OS keychain) and `token "<name>"` (token source).

## Routing

- Incoming paths are cleaned first (`.`/`..` segments, including `%2E`-encoded, and
  repeated slashes) so requests can't climb above an upstream's base path.
- Longest prefix match, on path-segment boundaries (`/git` does not match `/github`).
- Prefix is stripped; remainder is joined onto the upstream's base path; query preserved.
- `Host` set to upstream host.
- Configured headers always **overwrite** client-supplied ones.
- Responses stream (`FlushInterval: -1`) so SSE works.
- Unmatched paths → 404 with JSON listing available prefixes.
- 3xx redirects pass through untouched (rewriting `Location` is a possible later feature).

## Secrets

- OS keychain via `github.com/zalando/go-keyring`; service `pcp`, account `<secret name>`.
- Loaded once at `serve` startup and cached (avoids repeated macOS keychain prompts).
  `SIGHUP` reloads config + secrets.
- Startup fails fast if a referenced secret is missing.

## Token sources

- `oauth2_client_credentials` built on `golang.org/x/oauth2/clientcredentials`
  (standard form-encoded token endpoint, JSON response with `access_token`/`expires_in`).
- Lazy: fetched on the first request that needs it, so a dead auth server only breaks
  its own routes.
- Cached in memory until shortly before expiry; never persisted.
- Upstream 401 → invalidate cached token so the next request refetches (no automatic
  retry of the failed request).
- Token fetch failure → 502 with JSON error naming the source and auth-server status;
  auth-server bodies are not echoed.
- `type` is a discriminator so other flows can be added later.

## CLI (stdlib `flag`)

| Command | Purpose |
|---|---|
| `pcp serve [--config]` | Run the proxy |
| `pcp routes` | List prefixes → upstreams (no secrets) |
| `pcp secret set <name>` | Store a keychain entry (no-echo prompt or stdin) |
| `pcp secret rm <name>` | Delete a keychain entry |
| `pcp check [--fetch]` | Validate config and that referenced secrets resolve; `--fetch` performs real token exchanges and reports expiry (never prints tokens) |

`GET /_pcp/routes` returns the route list as JSON for LLM discovery.

## Safety (best effort)

- Binds `127.0.0.1` by default.
- Access logs: method, route, status, latency. Never header values or tokens.

## Layout

```
main.go              # subcommand dispatch
internal/config/     # load, validate, template parsing
internal/secrets/    # Store interface, keyring impl, in-memory fake
internal/tokens/     # Source interface, client-credentials impl, cache
internal/proxy/      # router + httputil.ReverseProxy (Rewrite func)
```

## Milestones

1. **Config + routing** — config loading/validation; table tests for path rewrite
   (prefix boundaries, trailing slashes, upstream base paths, query strings).
2. **Proxy core** — reverse proxy with in-memory secret store; `httptest` upstream tests
   for header injection and client-header overwrite.
3. **Token sources** — client-credentials source against a fake `/oauth/token`: caching,
   expiry refresh, concurrent requests → one fetch, 401 invalidation, 502 on failure.
4. **Keychain** — keyring store; `secret set/rm` and `check [--fetch]` commands.
5. **Serve** — `serve`, `routes`, `/_pcp/routes`, SIGHUP reload.
6. **Docs** — README usage and a sample LLM instruction snippet.
