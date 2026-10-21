// Command zandu-forwarder runs the permission-aware API forwarder.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sairam/zandu/forwarder"
)

const usage = `Usage:
  zandu-forwarder [serve] [flags]   run the proxy and admin UI
  zandu-forwarder check [flags]     validate the configuration file
  zandu-forwarder token             print a new client token and its hash

Flags for serve and check:
`

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "check":
		err = check(args)
	case "token":
		err = printToken()
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type options struct {
	config         string
	listen         string
	adminListen    string
	trustedProxies string
	auditSize      int
}

func parseFlags(name string, args []string) (*options, error) {
	o := &options{}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }
	fs.StringVar(&o.config, "config", env("ZANDU_CONFIG", "forwarder.json"), "configuration file (env ZANDU_CONFIG)")
	fs.StringVar(&o.listen, "listen", env("ZANDU_LISTEN", ":8080"), "proxy listen address (env ZANDU_LISTEN)")
	fs.StringVar(&o.adminListen, "admin-listen", env("ZANDU_ADMIN_LISTEN", "127.0.0.1:8081"), "admin UI listen address; empty disables it (env ZANDU_ADMIN_LISTEN)")
	fs.StringVar(&o.trustedProxies, "trusted-proxies", env("ZANDU_TRUSTED_PROXIES", ""), "comma-separated CIDRs whose X-Forwarded-For is trusted (env ZANDU_TRUSTED_PROXIES)")
	fs.IntVar(&o.auditSize, "audit-size", 1000, "number of recent requests kept for the audit view")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return o, nil
}

func serve(args []string) error {
	o, err := parseFlags("serve", args)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	var trusted []netip.Prefix
	for _, s := range strings.Split(o.trustedProxies, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("trusted-proxies: %w", err)
		}
		trusted = append(trusted, p)
	}

	store, err := forwarder.OpenStore(o.config)
	if err != nil {
		return err
	}
	audit := forwarder.NewAuditLog(o.auditSize)
	proxy := forwarder.NewProxy(store, audit, forwarder.ProxyOptions{TrustedProxies: trusted, Logger: logger})

	servers := []*http.Server{newServer(o.listen, proxy)}
	if o.adminListen != "" {
		token := os.Getenv("ZANDU_ADMIN_TOKEN")
		if len(token) < 16 {
			return errors.New("ZANDU_ADMIN_TOKEN must be set to at least 16 characters, or disable the admin UI with -admin-listen=''")
		}
		servers = append(servers, newServer(o.adminListen, forwarder.NewAdmin(store, audit, token)))
	}

	errc := make(chan error, len(servers))
	for _, s := range servers {
		logger.Info("listening", "addr", s.Addr)
		go func() {
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case err := <-errc:
			return err
		case s := <-sig:
			if s == syscall.SIGHUP {
				if err := store.Reload(); err != nil {
					logger.Error("reload failed; keeping previous configuration", "error", err)
				} else {
					logger.Info("configuration reloaded")
				}
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			for _, srv := range servers {
				srv.Shutdown(ctx)
			}
			return nil
		}
	}
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func check(args []string) error {
	o, err := parseFlags("check", args)
	if err != nil {
		return err
	}
	if _, err := os.Stat(o.config); err != nil {
		return err
	}
	if _, err := forwarder.OpenStore(o.config); err != nil {
		return err
	}
	fmt.Println("configuration is valid")
	return nil
}

func printToken() error {
	token, hash, err := forwarder.NewToken()
	if err != nil {
		return err
	}
	fmt.Printf("token:      %s\ntoken_hash: %s\n", token, hash)
	return nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
