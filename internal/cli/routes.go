package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/PatOConnor43/pcp/internal/config"
	"github.com/PatOConnor43/pcp/internal/proxy"
)

func runRoutes(args []string, env Env) error {
	fs := newFlagSet("routes", env)
	configPath := configFlag(fs)
	asJSON := fs.Bool("json", false, "output JSON")
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

	base := "http://" + cfg.Listen
	routes := proxy.Routes(cfg.Routes)
	if *asJSON {
		type route struct {
			URL string `json:"url"`
			proxy.RouteInfo
		}
		out := make([]route, 0, len(routes))
		for _, r := range routes {
			out = append(out, route{base + r.Prefix, r})
		}
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"routes": out})
	}

	tw := tabwriter.NewWriter(env.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "LOCAL\tUPSTREAM")
	for _, r := range routes {
		fmt.Fprintf(tw, "%s%s\t%s\n", base, r.Prefix, r.Upstream)
	}
	return tw.Flush()
}
