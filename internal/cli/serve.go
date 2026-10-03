package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/PatOConnor43/pcp/internal/config"
	"github.com/PatOConnor43/pcp/internal/proxy"
)

const shutdownTimeout = 10 * time.Second

func runServe(args []string, env Env) error {
	fs := newFlagSet("serve", env)
	configPath := configFlag(fs)
	listen := fs.String("listen", "", "address to listen on (overrides config)")
	debug := fs.Bool("debug", false, "enable debug logging")
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
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(env.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, p, err := loadProxy(path, env, logger)
	if err != nil {
		return err
	}
	addr := cfg.Listen
	if *listen != "" {
		addr = *listen
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if !isLoopback(ln.Addr()) {
		logger.Warn("listening on a non-loopback address; anyone who can reach it can use your credentials", "addr", ln.Addr())
	}

	var h swapHandler
	h.p.Store(p)
	srv := &http.Server{Handler: &h, ReadHeaderTimeout: 10 * time.Second}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()
	logger.Info("pcp listening", "addr", "http://"+ln.Addr().String(), "routes", len(cfg.Routes), "config", path)
	if env.Listening != nil {
		env.Listening(ln.Addr())
	}

	ctx := env.Context
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		select {
		case err := <-serveErr:
			return err
		case <-env.Hangup:
			newCfg, newP, err := loadProxy(path, env, logger)
			if err != nil {
				logger.Error("reload failed; keeping previous config", "err", err)
				continue
			}
			if *listen == "" && newCfg.Listen != cfg.Listen {
				logger.Warn("listen address changed; restart pcp to apply it", "current", addr, "configured", newCfg.Listen)
			}
			h.p.Store(newP)
			cfg = newCfg
			logger.Info("reloaded config", "routes", len(cfg.Routes))
		case <-ctx.Done():
			logger.Info("shutting down")
			sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			if err := srv.Shutdown(sctx); err != nil {
				// Long-lived streams didn't finish in time.
				srv.Close()
			}
			if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		}
	}
}

// loadProxy loads config and builds a proxy, reading secrets fresh from the
// store.
func loadProxy(path string, env Env, logger *slog.Logger) (*config.Config, *proxy.Proxy, error) {
	cfg, err := loadConfig(path)
	if err != nil {
		return nil, nil, err
	}
	p, err := proxy.New(cfg, proxy.Options{Secrets: env.Secrets, Transport: env.Transport, Logger: logger})
	if err != nil {
		return nil, nil, err
	}
	return cfg, p, nil
}

// swapHandler serves with the current proxy. Reloads swap in a new one;
// in-flight requests finish on the proxy they started with.
type swapHandler struct {
	p atomic.Pointer[proxy.Proxy]
}

func (h *swapHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.p.Load().ServeHTTP(w, r)
}

func isLoopback(addr net.Addr) bool {
	tcp, ok := addr.(*net.TCPAddr)
	return ok && tcp.IP.IsLoopback()
}
