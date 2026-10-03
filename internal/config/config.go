// Package config loads and validates the pcp configuration file.
package config

import (
	"errors"
	"fmt"
	"maps"
	"net/textproto"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/goccy/go-yaml"
)

const (
	DefaultListen = "127.0.0.1:7277"

	// ReservedPrefix is used for pcp's own endpoints (e.g. /_pcp/routes).
	ReservedPrefix = "/_pcp"
	// LLMsPath serves usage docs for LLM agents, following the llms.txt
	// convention. Also reserved.
	LLMsPath = "/llms.txt"

	TypeOAuth2ClientCredentials = "oauth2_client_credentials"
)

type Config struct {
	Listen string                 `yaml:"listen"`
	Tokens map[string]TokenSource `yaml:"tokens"`
	Routes []Route                `yaml:"routes"`
}

type TokenSource struct {
	Type         string            `yaml:"type"`
	TokenURL     string            `yaml:"token_url"`
	ClientID     Template          `yaml:"client_id"`
	ClientSecret Template          `yaml:"client_secret"`
	Scopes       []string          `yaml:"scopes"`
	Params       map[string]string `yaml:"params"`
}

type Route struct {
	Prefix   string              `yaml:"prefix"`
	Upstream string              `yaml:"upstream"`
	Headers  map[string]Template `yaml:"headers"`

	// UpstreamURL is Upstream parsed, with any trailing slash removed.
	UpstreamURL *url.URL `yaml:"-"`
}

// DefaultPath returns $XDG_CONFIG_HOME/pcp/config.yaml, falling back to
// ~/.config/pcp/config.yaml.
func DefaultPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "pcp", "config.yaml"), nil
}

// Load reads, parses, and validates the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse parses and validates config YAML.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.UnmarshalWithOptions(data, &cfg, yaml.Strict()); err != nil {
		return nil, errors.New(yaml.FormatError(err, false, true))
	}
	if cfg.Listen == "" {
		cfg.Listen = DefaultListen
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(c.Tokens)) {
		ts := c.Tokens[name]
		if err := ts.validate(); err != nil {
			errs = append(errs, fmt.Errorf("tokens.%s: %w", name, err))
		}
	}
	if len(c.Routes) == 0 {
		errs = append(errs, errors.New("routes: at least one route is required"))
	}
	seen := map[string]bool{}
	for i := range c.Routes {
		r := &c.Routes[i]
		if err := r.normalize(); err != nil {
			errs = append(errs, fmt.Errorf("routes[%d]: %w", i, err))
			continue
		}
		if seen[r.Prefix] {
			errs = append(errs, fmt.Errorf("routes[%d]: duplicate prefix %q", i, r.Prefix))
		}
		seen[r.Prefix] = true
		for _, h := range slices.Sorted(maps.Keys(r.Headers)) {
			for _, tok := range r.Headers[h].Tokens() {
				if _, ok := c.Tokens[tok]; !ok {
					errs = append(errs, fmt.Errorf("routes[%d].headers.%s: unknown token source %q", i, h, tok))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// SecretNames returns every secret referenced anywhere in the config, sorted.
func (c *Config) SecretNames() []string {
	var names []string
	add := func(t Template) {
		for _, s := range t.Secrets() {
			names = appendUnique(names, s)
		}
	}
	for _, ts := range c.Tokens {
		add(ts.ClientID)
		add(ts.ClientSecret)
	}
	for _, r := range c.Routes {
		for _, t := range r.Headers {
			add(t)
		}
	}
	slices.Sort(names)
	return names
}

func (ts *TokenSource) validate() error {
	switch ts.Type {
	case TypeOAuth2ClientCredentials:
	case "":
		return errors.New("type is required")
	default:
		return fmt.Errorf("unsupported type %q", ts.Type)
	}
	var errs []error
	if _, err := parseHTTPURL(ts.TokenURL); err != nil {
		errs = append(errs, fmt.Errorf("token_url: %w", err))
	}
	for _, f := range []struct {
		name string
		t    Template
	}{{"client_id", ts.ClientID}, {"client_secret", ts.ClientSecret}} {
		field, t := f.name, f.t
		if t.Raw() == "" {
			errs = append(errs, fmt.Errorf("%s is required", field))
		}
		if len(t.Tokens()) > 0 {
			errs = append(errs, fmt.Errorf("%s: token sources cannot reference other tokens", field))
		}
	}
	return errors.Join(errs...)
}

func (r *Route) normalize() error {
	if r.Prefix == "" {
		return errors.New("prefix is required")
	}
	if !strings.HasPrefix(r.Prefix, "/") {
		return fmt.Errorf("prefix %q must start with /", r.Prefix)
	}
	for _, c := range r.Prefix {
		if !isPrefixChar(c) {
			return fmt.Errorf("prefix %q contains invalid character %q", r.Prefix, c)
		}
	}
	r.Prefix = path.Clean(r.Prefix)
	if r.Prefix == "/" {
		return errors.New("prefix must not be /")
	}
	for _, reserved := range []string{ReservedPrefix, LLMsPath} {
		if r.Prefix == reserved || strings.HasPrefix(r.Prefix, reserved+"/") {
			return fmt.Errorf("prefix %q is reserved", reserved)
		}
	}

	u, err := parseHTTPURL(r.Upstream)
	if err != nil {
		return fmt.Errorf("upstream: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = strings.TrimRight(u.RawPath, "/")
	r.UpstreamURL = u

	canonical := map[string]string{}
	for _, name := range slices.Sorted(maps.Keys(r.Headers)) {
		if !isToken(name) {
			return fmt.Errorf("headers: invalid header name %q", name)
		}
		key := textproto.CanonicalMIMEHeaderKey(name)
		if prev, ok := canonical[key]; ok {
			return fmt.Errorf("headers: %q and %q are the same header", prev, name)
		}
		canonical[key] = name
	}
	return nil
}

func parseHTTPURL(s string) (*url.URL, error) {
	if s == "" {
		return nil, errors.New("is required")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%q must use http or https", s)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%q has no host", s)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("%q must not contain userinfo, query, or fragment", s)
	}
	return u, nil
}

// isPrefixChar reports whether c is an unreserved URL path character, so that a
// prefix's escaped and unescaped forms are identical.
func isPrefixChar(c rune) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		strings.ContainsRune("-._~/", c)
}

// isToken reports whether s is a valid HTTP header field name (RFC 9110 token).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		alnum := 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9'
		if !alnum && !strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
			return false
		}
	}
	return true
}
