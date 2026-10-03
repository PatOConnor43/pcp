// Command pcp is a local reverse proxy that injects credentials into requests,
// so tools like LLM agents can call APIs without handling secrets.
package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"golang.org/x/term"

	"github.com/PatOConnor43/pcp/internal/cli"
	"github.com/PatOConnor43/pcp/internal/secrets"
)

// version is set at build time by release builds (-ldflags "-X main.version=...").
var version string

// buildVersion returns the release version, falling back to the module
// version recorded by go install.
func buildVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	hangup := make(chan os.Signal, 1)
	signal.Notify(hangup, syscall.SIGHUP)

	env := cli.Env{
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Version: buildVersion(),
		Secrets: secrets.Keyring{},
		Context: ctx,
		Hangup:  hangup,
	}
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		env.ReadPassword = func() ([]byte, error) { return term.ReadPassword(fd) }
	}
	code := cli.Run(os.Args[1:], env)
	stop()
	os.Exit(code)
}
