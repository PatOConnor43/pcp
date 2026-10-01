// Package tokens provides cached, refreshable credentials obtained from an
// auth server, such as OAuth2 client-credentials access tokens.
package tokens

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/PatOConnor43/pcp/internal/config"
)

// refreshBefore is how long before expiry a cached token is replaced.
const refreshBefore = 30 * time.Second

// Source produces a token, fetching and caching it as needed.
type Source interface {
	// Token returns a valid token, fetching one if none is cached or the
	// cached one is about to expire. Errors are *FetchError.
	Token(ctx context.Context) (string, error)
	// Invalidate drops the cached token if it equals tok, so the next call
	// to Token fetches a new one. Passing the rejected value avoids
	// discarding a token that was already refreshed by another request.
	Invalidate(tok string)
}

// FetchError reports a failure to obtain a token. Its message never includes
// the auth server's response body, which may echo credentials.
type FetchError struct {
	Source string
	Status int    // auth server HTTP status, or 0 if no response
	Code   string // RFC 6749 error code (e.g. invalid_client), if provided
	Err    error  // underlying error when Status is 0
}

func (e *FetchError) Error() string {
	if e.Status != 0 {
		msg := fmt.Sprintf("token source %q: auth server returned %d", e.Source, e.Status)
		if e.Code != "" {
			msg += fmt.Sprintf(" (%s)", e.Code)
		}
		return msg
	}
	return fmt.Sprintf("token source %q: %v", e.Source, e.Err)
}

func (e *FetchError) Unwrap() error { return e.Err }

// NewSources builds a Source for each configured token source. secret
// resolves `secret` references in credential fields. client is used for
// token requests.
func NewSources(cfgs map[string]config.TokenSource, secret func(string) (string, error), client *http.Client) (map[string]Source, error) {
	funcs := map[string]any{"secret": secret}
	render := func(t config.Template) (string, error) {
		tpl, err := t.Compile(funcs)
		if err != nil {
			return "", err
		}
		var sb strings.Builder
		if err := tpl.Execute(&sb, nil); err != nil {
			return "", err
		}
		return sb.String(), nil
	}

	sources := map[string]Source{}
	for _, name := range slices.Sorted(maps.Keys(cfgs)) {
		c := cfgs[name]
		switch c.Type {
		case config.TypeOAuth2ClientCredentials:
			id, err := render(c.ClientID)
			if err != nil {
				return nil, fmt.Errorf("token source %q: client_id: %w", name, err)
			}
			secret, err := render(c.ClientSecret)
			if err != nil {
				return nil, fmt.Errorf("token source %q: client_secret: %w", name, err)
			}
			params := url.Values{}
			for k, v := range c.Params {
				params.Set(k, v)
			}
			sources[name] = NewClientCredentials(name, clientcredentials.Config{
				ClientID:       id,
				ClientSecret:   secret,
				TokenURL:       c.TokenURL,
				Scopes:         c.Scopes,
				EndpointParams: params,
			}, client)
		default:
			return nil, fmt.Errorf("token source %q: unsupported type %q", name, c.Type)
		}
	}
	return sources, nil
}

// ClientCredentials is a Source using the OAuth2 client-credentials grant.
type ClientCredentials struct {
	name   string
	cfg    clientcredentials.Config
	client *http.Client

	// mu is held during fetches so concurrent callers share one request.
	mu  sync.Mutex
	tok *oauth2.Token
}

func NewClientCredentials(name string, cfg clientcredentials.Config, client *http.Client) *ClientCredentials {
	if client == nil {
		client = http.DefaultClient
	}
	return &ClientCredentials{name: name, cfg: cfg, client: client}
}

func (c *ClientCredentials) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok != nil && (c.tok.Expiry.IsZero() || time.Until(c.tok.Expiry) > refreshBefore) {
		return c.tok.AccessToken, nil
	}

	tok, err := c.cfg.Token(context.WithValue(ctx, oauth2.HTTPClient, c.client))
	if err != nil {
		if re, ok := errors.AsType[*oauth2.RetrieveError](err); ok && re.Response != nil {
			return "", &FetchError{Source: c.name, Status: re.Response.StatusCode, Code: re.ErrorCode}
		}
		return "", &FetchError{Source: c.name, Err: err}
	}
	c.tok = tok
	return tok.AccessToken, nil
}

func (c *ClientCredentials) Invalidate(tok string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok != nil && c.tok.AccessToken == tok {
		c.tok = nil
	}
}
