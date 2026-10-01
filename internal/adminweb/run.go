package adminweb

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/R055LE/secrets-broker/internal/execx"
)

func Run(args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("must run as root")
	}
	if len(args) == 1 && args[0] == "validate" {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
		if err != nil {
			return errors.New("reading admin web configuration failed")
		}
		cfg, err := ParseConfig(data)
		if err != nil {
			return err
		}
		if err := CheckTailscale(context.Background(), cfg, execx.OSRunner{}); err != nil {
			return err
		}
		return checkSocket()
	}
	if len(args) != 0 && (len(args) != 1 || args[0] != "check") {
		return errors.New("usage: secrets-broker-admin-web [check|validate]")
	}
	cfg, err := LoadConfig()
	if err != nil {
		return err
	}
	if err := CheckTailscale(context.Background(), cfg, execx.OSRunner{}); err != nil {
		return err
	}
	if err := checkSocket(); err != nil {
		return err
	}
	if len(args) == 1 {
		return nil
	}
	listener, err := activatedListener()
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	server := &http.Server{
		Handler: NewServer(cfg), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 40 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: log.New(io.Discard, "", 0),
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			_, trusted := conn.(*peerConn)
			return context.WithValue(ctx, peerKey{}, trusted)
		},
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	finished := make(chan struct{})
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
			defer cancel()
			_ = server.Shutdown(shutdownCtx)
		case <-finished:
		}
	}()
	err = server.Serve(listener)
	close(finished)
	<-shutdownDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
