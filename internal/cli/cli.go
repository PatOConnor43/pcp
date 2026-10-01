// Package cli implements pcp's command-line interface.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/PatOConnor43/pcp/internal/config"
	"github.com/PatOConnor43/pcp/internal/secrets"
)

// Env is the process environment commands run in.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	Secrets secrets.Manager
	// Transport is used for outbound HTTP. Nil means http.DefaultTransport.
	Transport http.RoundTripper
	// ReadPassword reads a line from the terminal without echoing it. Nil
	// when stdin is not a terminal.
	ReadPassword func() ([]byte, error)

	// Context stops long-running commands (serve) when canceled. Nil means
	// run until the server fails.
	Context context.Context
	// Hangup delivers reload requests to serve (SIGHUP).
	Hangup <-chan os.Signal
	// Listening, if set, is called once serve is accepting connections.
	Listening func(net.Addr)
}

const usage = `pcp - credential-injecting reverse proxy

Usage:
  pcp serve [flags]         Run the proxy (SIGHUP reloads config and secrets)
  pcp routes [flags]        List routes and their local URLs
  pcp secret set <name>     Store a secret in the OS keychain (prompts, or reads stdin)
  pcp secret rm <name>      Delete a secret from the OS keychain
  pcp check [flags]         Validate config and check referenced secrets resolve
`

// errUsage signals a usage error whose message has already been printed.
var errUsage = errors.New("usage")

// Run executes the command in args and returns the process exit code.
func Run(args []string, env Env) int {
	err := run(args, env)
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errUsage):
		return 2
	case errors.Is(err, flag.ErrHelp):
		return 0
	default:
		fmt.Fprintf(env.Stderr, "pcp: %v\n", err)
		return 1
	}
}

func run(args []string, env Env) error {
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, usage)
		return errUsage
	}
	switch args[0] {
	case "secret":
		return runSecret(args[1:], env)
	case "serve":
		return runServe(args[1:], env)
	case "routes":
		return runRoutes(args[1:], env)
	case "check":
		return runCheck(args[1:], env)
	case "help", "-h", "--help":
		fmt.Fprint(env.Stdout, usage)
		return nil
	default:
		fmt.Fprintf(env.Stderr, "unknown command %q\n\n%s", args[0], usage)
		return errUsage
	}
}

// configFlag registers the --config flag shared by commands that load config.
func configFlag(fs *flag.FlagSet) func() (string, error) {
	path := fs.String("config", "", "config file (default $XDG_CONFIG_HOME/pcp/config.yaml or ~/.config/pcp/config.yaml)")
	return func() (string, error) {
		if *path != "" {
			return *path, nil
		}
		return config.DefaultPath()
	}
}

func newFlagSet(name string, env Env) *flag.FlagSet {
	fs := flag.NewFlagSet("pcp "+name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	return fs
}

// parseFlags parses args, mapping flag errors (already printed) to errUsage.
func parseFlags(fs *flag.FlagSet, args []string) error {
	err := fs.Parse(args)
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		return errUsage
	}
	return err
}

func validSecretName(name string) error {
	if name == "" {
		return errors.New("secret name must not be empty")
	}
	if strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return errors.New("secret name must not contain control characters")
	}
	return nil
}
