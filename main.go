// Command pcp is a local reverse proxy that injects credentials into requests,
// so tools like LLM agents can call APIs without handling secrets.
package main

import (
	"os"

	"golang.org/x/term"

	"github.com/PatOConnor43/pcp/internal/cli"
	"github.com/PatOConnor43/pcp/internal/secrets"
)

func main() {
	env := cli.Env{
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Secrets: secrets.Keyring{},
	}
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		env.ReadPassword = func() ([]byte, error) { return term.ReadPassword(fd) }
	}
	os.Exit(cli.Run(os.Args[1:], env))
}
