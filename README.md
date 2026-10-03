# Pat's Curl Proxy

This is a project meant to act as a curl proxy to automatically add headers to requests. More specifically meant to act as a credential manager so LLMs can make curl requests without needing to juggle credentials.

pcp is a local reverse proxy. You map a path prefix to an upstream API and the
headers it needs; pcp keeps the secrets in your OS keychain and adds them to
every request. The client (an LLM agent, a script, you) only ever sees
`http://127.0.0.1:8080/...`.

```
curl -s localhost:8080/github/user/repos?per_page=5
  → GET https://api.github.com/user/repos?per_page=5
    Authorization: Bearer <from keychain>
```

No MITM or CA certificates are involved: clients speak plain HTTP to pcp on
loopback, and pcp speaks HTTPS to the upstream.

## Install

With [Homebrew](https://brew.sh) (macOS and Linux):

```sh
brew install --cask patoconnor43/tap/pcp
```

Or download the archive for your platform from the
[releases page](https://github.com/PatOConnor43/pcp/releases/latest), extract
it, and put `pcp` somewhere on your `PATH`:

```sh
# macOS (Apple silicon) example; pick the archive matching your OS/arch
VERSION=0.1.0
curl -sSL "https://github.com/PatOConnor43/pcp/releases/download/v${VERSION}/pcp_${VERSION}_darwin_arm64.tar.gz" | tar -xz pcp
sudo mv pcp /usr/local/bin/
pcp version
```

Each release includes a `checksums.txt` for verifying downloads. On macOS, if
you downloaded the archive with a browser and Gatekeeper blocks the binary, run
`xattr -d com.apple.quarantine pcp`.

Or build from source (requires Go 1.26+):

```sh
go install github.com/PatOConnor43/pcp@latest
```

Secrets are stored in the macOS Keychain, Linux Secret Service (GNOME Keyring,
KWallet), or Windows Credential Manager. On Linux, a Secret Service provider
must be running; headless servers often don't have one.

## Quick start

1. Create `~/.config/pcp/config.yaml`:

   ```yaml
   routes:
     - prefix: /github
       upstream: https://api.github.com
       headers:
         Authorization: 'Bearer {{ secret "github" }}'
   ```

2. Store the secret (prompts without echoing, or reads stdin):

   ```sh
   pcp secret set github
   # or: gh auth token | pcp secret set github
   ```

3. Check and run:

   ```sh
   pcp check
   pcp serve
   ```

4. Use it:

   ```sh
   curl -s localhost:8080/github/user
   ```

## Configuration

Default location: `$XDG_CONFIG_HOME/pcp/config.yaml`, falling back to
`~/.config/pcp/config.yaml`. Every command accepts `--config <path>`.
See [`examples/config.yaml`](examples/config.yaml) for Bearer, Basic, API-key,
and OAuth2 examples.

```yaml
listen: 127.0.0.1:8080        # default

tokens:                       # optional
  myapi:
    type: oauth2_client_credentials
    token_url: https://auth.example.com/oauth/token
    client_id: my-client-id
    client_secret: '{{ secret "myapi-client-secret" }}'
    scopes: [read, write]     # optional
    params:                   # optional extra form fields
      audience: https://api.example.com

routes:
  - prefix: /myapi
    upstream: https://api.example.com/v1
    headers:
      Authorization: 'Bearer {{ token "myapi" }}'
      X-Static: '{{ secret "other" }}'
```

Unknown fields are errors, and all validation problems are reported at once.

### Header templates

Header values (and token source `client_id`/`client_secret`) are Go templates
with two functions:

| Function | Value |
|---|---|
| `{{ secret "name" }}` | Keychain entry `name` (service `pcp`) |
| `{{ token "name" }}` | Current token from the token source `name` |

Arguments must be string literals so pcp can verify every reference before
serving. Quote template values in YAML (`'...'`), since `{` starts a YAML map.

### Routing

- `/<prefix>/<rest>?<query>` is forwarded to `<upstream>/<rest>?<query>`.
- The longest matching prefix wins, on whole path segments only: `/git` does
  not match `/github/...`.
- Paths are cleaned before matching (`..`, `.`, `%2E%2E`, `//`), so a request
  can't escape its upstream's base path. Encoded slashes (`%2F`) are preserved.
- Configured headers replace any the client sent. Other client headers, the
  method, and the body pass through unchanged. No `X-Forwarded-*` headers are
  added.
- Responses are streamed (SSE works). Redirects pass through unchanged, so a
  client following an absolute redirect to the upstream will bypass pcp.
- Unmatched paths return `404` with a JSON list of routes.
- `/_pcp` is reserved for pcp's own endpoints.

### Secrets

Secrets are read from the keychain once at startup (avoiding repeated keychain
prompts) and kept in memory. pcp refuses to start if any referenced secret is
missing. Send `SIGHUP` to pick up changed secrets.

Secret values must be a single line.

### OAuth2 client credentials

`oauth2_client_credentials` token sources use the standard client-credentials
grant against `token_url` (form-encoded request; JSON response with
`access_token` and `expires_in`).

- Tokens are fetched on first use, not at startup, so a down auth server only
  affects routes that need it.
- Tokens are cached in memory until 30s before expiry. Concurrent requests
  share a single fetch.
- If an upstream returns `401`, the token used is discarded and the next
  request fetches a new one. The `401` itself is returned to the client; pcp
  doesn't retry.
- If the token fetch fails, the client gets `502` with a message like
  `token source "myapi": auth server returned 401 (invalid_client)`. Auth
  server response bodies are never forwarded.

## Commands

| Command | Description |
|---|---|
| `pcp serve [--listen addr] [--debug]` | Run the proxy. |
| `pcp routes [--json]` | List routes with their local URLs. Doesn't read the keychain. |
| `pcp secret set <name>` | Store a secret. Prompts without echo on a terminal; otherwise reads stdin (one trailing newline is trimmed). |
| `pcp secret rm <name>` | Delete a secret. |
| `pcp check [--fetch]` | Validate config and report each secret as ok/MISSING. `--fetch` also requests a token from each token source and reports its expiry (never the token). Exits 1 on any problem. |
| `pcp version` | Print the pcp version. |

`pcp serve` reloads config and secrets on `SIGHUP`
(`pkill -HUP -x pcp`). If the new config is invalid, the error is logged and
the previous config keeps serving. Reloading clears cached tokens. Changing
`listen` requires a restart. `SIGINT`/`SIGTERM` shut down gracefully.

### HTTP endpoints

`GET /_pcp/routes` returns the configured routes (no credentials) so clients
can discover what's available:

```json
{
  "routes": [{"prefix": "/github", "upstream": "https://api.github.com"}],
  "usage": "Send requests to <this server><prefix>/<path>. They are forwarded to <upstream>/<path> with credentials added."
}
```

## Using pcp with an LLM agent

Add something like this to your agent's instructions (e.g. `CLAUDE.md`):

```markdown
## API access

A local proxy at http://127.0.0.1:8080 adds credentials to API requests.
Never ask for, look up, or include API tokens yourself.

- List available APIs: `curl -s http://127.0.0.1:8080/_pcp/routes`
- Call an API by putting its route prefix before the API path, e.g.
  `curl -s http://127.0.0.1:8080/github/user` instead of
  `curl -s https://api.github.com/user`.
- Don't set `Authorization` or other credential headers; the proxy sets them.
- A `502` mentioning "token source" means the proxy couldn't authenticate.
  Report it to the user instead of retrying.
```

`pcp routes` prints the exact URLs to paste into instructions.

## Security notes

pcp keeps secrets out of the agent's context, not out of its reach. Understand
what that does and doesn't protect:

- **Any local process can use your credentials** by talking to pcp. Keep
  `listen` on loopback; pcp warns if it isn't.
- **Every path and method on a configured upstream is reachable**, including
  destructive ones. Scope the credentials you give pcp (read-only tokens,
  minimal OAuth scopes) to what the agent should be able to do.
- **Responses pass through unchanged.** An upstream that echoes credentials
  back in its response would reveal them to the client.
- pcp never logs header values, secrets, or tokens. Access logs contain the
  method, path (without query string), route, status, and duration.
