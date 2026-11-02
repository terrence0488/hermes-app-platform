// hermes-app-router is the access lock for apps published on a Hermes host. It sits behind one
// wildcard tunnel route, verifies the Cloudflare Access token itself, and proxies a request to an
// app only for a team member or that app's guest. Anything it cannot confirm is refused.
//
// It uses the Go standard library only: net/http for the server, httputil.ReverseProxy for
// streaming and WebSockets, crypto/rsa for the token signature.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func newServer(config *Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:    config.Listen,
		Handler: handler,
		// No read or write timeout on purpose: uploads, streams and WebSockets can run for hours.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
}

// check tries everything the router needs, for use before it takes any traffic.
func check(config *Config, verifier *Verifier, store *Store) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := verifier.Refresh(ctx); err != nil {
		return fmt.Errorf("fetch Access keys from %s: %w", config.certsURL(), err)
	}
	team, bad, err := store.Team()
	if err != nil {
		return fmt.Errorf("team file: %w", err)
	}
	if _, err := store.App("hermes-app-router-check"); err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	fmt.Printf("ok: Access keys fetched, %d team members, %d team lines ignored\n", len(team), len(bad))
	return nil
}

func main() {
	configPath := flag.String("config", "/etc/hermes-apps/router.json", "path to the settings file")
	checkOnly := flag.Bool("check", false, "check the config, team file, registry and Access keys, then exit")
	flag.Parse()
	log.SetFlags(0) // journald adds the time

	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	verifier := newVerifier(config)
	store := newStore(config)
	if *checkOnly {
		if err := check(config, verifier, store); err != nil {
			log.Fatal(err)
		}
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// With no keys yet, every request is refused until a fetch succeeds.
	go verifier.RunRefresh(ctx)
	server := newServer(config, newRouter(config, verifier, store))
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		_ = server.Close()
	}()
	log.Printf("listening on %s for *.%s", config.Listen, config.Domain)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("server stopped: %v", err)
		os.Exit(1)
	}
}
