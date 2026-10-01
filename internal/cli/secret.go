package cli

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/PatOConnor43/pcp/internal/secrets"
)

// maxSecretSize bounds secrets read from stdin.
const maxSecretSize = 64 << 10

const secretUsage = `Usage:
  pcp secret set <name>   Store a secret (prompts without echo, or reads stdin)
  pcp secret rm <name>    Delete a secret
`

func runSecret(args []string, env Env) error {
	if len(args) != 2 || (args[0] != "set" && args[0] != "rm") {
		fmt.Fprint(env.Stderr, secretUsage)
		return errUsage
	}
	name := args[1]
	if err := validSecretName(name); err != nil {
		return err
	}

	if args[0] == "rm" {
		err := env.Secrets.Delete(name)
		if errors.Is(err, secrets.ErrNotFound) {
			return fmt.Errorf("secret %q not found", name)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(env.Stderr, "Deleted secret %q.\n", name)
		return nil
	}

	value, err := readSecret(name, env)
	if err != nil {
		return err
	}
	if err := env.Secrets.Set(name, value); err != nil {
		return err
	}
	fmt.Fprintf(env.Stderr, "Saved secret %q.\n", name)
	return nil
}

// readSecret prompts for a value on a terminal, or reads it from stdin.
func readSecret(name string, env Env) (string, error) {
	var value string
	if env.ReadPassword != nil {
		fmt.Fprintf(env.Stderr, "Value for %s: ", name)
		b, err := env.ReadPassword()
		fmt.Fprintln(env.Stderr)
		if err != nil {
			return "", fmt.Errorf("reading secret: %w", err)
		}
		value = string(b)
	} else {
		b, err := io.ReadAll(io.LimitReader(env.Stdin, maxSecretSize+1))
		if err != nil {
			return "", fmt.Errorf("reading secret from stdin: %w", err)
		}
		if len(b) > maxSecretSize {
			return "", fmt.Errorf("secret is larger than %d bytes", maxSecretSize)
		}
		// Allow `echo value | pcp secret set name`.
		value = strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	}

	if value == "" {
		return "", errors.New("secret value is empty")
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("secret value must be a single line with no NUL bytes")
	}
	return value, nil
}
