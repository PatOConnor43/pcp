package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PatOConnor43/pcp/internal/config"
)

// starterConfig is written by pcp init. It must pass validation.
var starterConfig = `# pcp config. Full reference:
# https://github.com/PatOConnor43/pcp#configuration
#
# Requests to http://` + config.DefaultListen + `<prefix>/<path> are forwarded
# to <upstream>/<path> with these headers set. Secrets live in the OS keychain:
#   pcp secret set github

routes:
  - prefix: /github
    upstream: https://api.github.com
    headers:
      Authorization: 'Bearer {{ secret "github" }}'
`

func runInit(args []string, env Env) error {
	fs := newFlagSet("init", env)
	configPath := configFlag(fs)
	force := fs.Bool("force", false, "overwrite an existing config file")
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

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if *force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s already exists (use --force to overwrite)", path)
	}
	if err != nil {
		return err
	}
	if _, err := f.WriteString(starterConfig); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	fmt.Fprintf(env.Stderr, `Wrote %s

Next steps:
  pcp secret set github   # or: gh auth token | pcp secret set github
  pcp check
  pcp serve
`, path)
	return nil
}
