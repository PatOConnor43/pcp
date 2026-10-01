package cli

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/PatOConnor43/pcp/internal/config"
	"github.com/PatOConnor43/pcp/internal/secrets"
	"github.com/PatOConnor43/pcp/internal/tokens"
)

const checkTimeout = 30 * time.Second

var errCheckFailed = errors.New("check failed")

func runCheck(args []string, env Env) error {
	fs := newFlagSet("check", env)
	configPath := configFlag(fs)
	fetch := fs.Bool("fetch", false, "fetch a token from each token source to verify credentials")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(env.Stderr, "unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return errUsage
	}

	path, err := configPath()
	if err != nil {
		return err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "Config %s: ok (%d routes, %d token sources)\n",
		path, len(cfg.Routes), len(cfg.Tokens))

	ok := true
	tw := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)

	resolved := map[string]string{}
	if names := cfg.SecretNames(); len(names) > 0 {
		fmt.Fprintln(tw, "\nSecrets:")
		for _, name := range names {
			v, err := env.Secrets.Get(name)
			switch {
			case err == nil:
				resolved[name] = v
				fmt.Fprintf(tw, "  %s\tok\n", name)
			case errors.Is(err, secrets.ErrNotFound):
				ok = false
				fmt.Fprintf(tw, "  %s\tMISSING\trun: pcp secret set %s\n", name, name)
			default:
				ok = false
				fmt.Fprintf(tw, "  %s\tERROR\t%v\n", name, err)
			}
		}
	}

	if len(cfg.Tokens) > 0 {
		fmt.Fprintln(tw, "\nToken sources:")
		client := &http.Client{Transport: env.Transport, Timeout: checkTimeout}
		secret := func(name string) (string, error) {
			v, ok := resolved[name]
			if !ok {
				return "", fmt.Errorf("secret %q unavailable", name)
			}
			return v, nil
		}
		for _, name := range slices.Sorted(maps.Keys(cfg.Tokens)) {
			status, good := checkTokenSource(name, cfg.Tokens[name], resolved, secret, client, *fetch)
			ok = ok && good
			fmt.Fprintf(tw, "  %s\t%s\n", name, status)
		}
	}
	tw.Flush()

	if !ok {
		return errCheckFailed
	}
	return nil
}

func checkTokenSource(name string, ts config.TokenSource, resolved map[string]string,
	secret func(string) (string, error), client *http.Client, fetch bool) (status string, ok bool) {
	var missing []string
	for _, t := range []config.Template{ts.ClientID, ts.ClientSecret} {
		for _, s := range t.Secrets() {
			if _, ok := resolved[s]; !ok && !slices.Contains(missing, s) {
				missing = append(missing, s)
			}
		}
	}
	if len(missing) > 0 {
		return "skipped\tmissing secrets: " + strings.Join(missing, ", "), false
	}
	if !fetch {
		return "not fetched\tuse --fetch to verify credentials", true
	}

	sources, err := tokens.NewSources(map[string]config.TokenSource{name: ts}, secret, client)
	if err != nil {
		return "FAILED\t" + err.Error(), false
	}
	src := sources[name]
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	if _, err := src.Token(ctx); err != nil {
		return "FAILED\t" + err.Error(), false
	}
	exp := src.Expiry()
	if exp.IsZero() {
		return "ok\tno expiry reported", true
	}
	return fmt.Sprintf("ok\texpires in %s", time.Until(exp).Round(time.Second)), true
}
