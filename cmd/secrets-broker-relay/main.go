// Command secrets-broker-relay runs the approval relay: two HTTP
// listeners (control + decision, see internal/relay) meant to run on a
// device the invoking agent has no access to — never the same host as
// the secrets-broker binary itself. See decisions/0008 and decisions/0009
// in the main repo for why that separation is the whole point.
//
// Uses stdlib flag, not cobra: a single-purpose daemon with no
// subcommands doesn't need cobra's machinery.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/R055LE/secrets-broker/internal/relay"
)

func main() {
	controlAddr := flag.String("control-addr", "127.0.0.1:7620",
		"listen address for the broker-facing control port (register/poll). "+
			"In production this MUST be your tailscale interface's IP, not 0.0.0.0 — "+
			"binding to 0.0.0.0 exposes this beyond the tailnet, defeating the whole point. "+
			"The 127.0.0.1 default is for local testing only.")
	decisionAddr := flag.String("decision-addr", "127.0.0.1:7621",
		"listen address for the approver-facing decision port. Same warning as -control-addr: "+
			"must be your tailscale IP in production, and MUST be reachable by a different, "+
			"narrower set of tailnet peers than -control-addr (enforced via Tailscale ACLs, "+
			"not by this program) — see decisions/0009.")
	ttl := flag.Duration("ttl", 5*time.Minute, "how long a pending request stays open before expiring")
	sweepInterval := flag.Duration("sweep-interval", time.Minute, "how often to sweep out closed/expired requests")
	sweepAfter := flag.Duration("sweep-after", time.Hour, "remove closed/expired requests once their deadline is this old")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if *controlAddr == *decisionAddr {
		logger.Error("control-addr and decision-addr must differ — the whole point is that they're reachable by different tailnet peers")
		os.Exit(1)
	}
	if err := validateListenAddr(*controlAddr); err != nil {
		logger.Error("invalid control-addr", "err", err)
		os.Exit(1)
	}
	if err := validateListenAddr(*decisionAddr); err != nil {
		logger.Error("invalid decision-addr", "err", err)
		os.Exit(1)
	}
	if *ttl <= 0 || *sweepInterval <= 0 || *sweepAfter < 0 {
		logger.Error("ttl and sweep-interval must be positive; sweep-after must not be negative")
		os.Exit(1)
	}

	store := relay.NewStore()

	controlServer := newHTTPServer(*controlAddr, withLogging(logger, "control", relay.NewControlHandler(store, *ttl)))
	decisionServer := newHTTPServer(*decisionAddr, withLogging(logger, "decision", relay.NewDecisionHandler(store)))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("control listener starting", "addr", *controlAddr)
		if err := controlServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("control listener failed", "err", err)
			os.Exit(1)
		}
	}()

	go func() {
		logger.Info("decision listener starting", "addr", *decisionAddr)
		if err := decisionServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("decision listener failed", "err", err)
			os.Exit(1)
		}
	}()

	go func() {
		ticker := time.NewTicker(*sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if removed := store.Sweep(*sweepAfter); removed > 0 {
					logger.Info("swept closed requests", "removed", removed)
				}
			}
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = controlServer.Shutdown(shutdownCtx)
	_ = decisionServer.Shutdown(shutdownCtx)
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func validateListenAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("host must be an IP address")
	}
	if ip.IsUnspecified() {
		return errors.New("unspecified addresses such as 0.0.0.0 and [::] are not allowed")
	}
	return nil
}

// withLogging logs method + path for every request — the request ID is
// part of the path (/requests/{id}[/decide]), so this is what lets an
// operator watching relay logs (or a future notification hook tailing
// them) see which ID a new pending request got, without the relay
// needing a "list pending requests" endpoint that anyone with control-port
// access could otherwise use to enumerate them.
func withLogging(logger *slog.Logger, port string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Info("request", "port", port, "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
