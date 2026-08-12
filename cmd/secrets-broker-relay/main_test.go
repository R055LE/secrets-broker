package main

import (
	"net/http"
	"testing"
	"time"
)

func TestValidateListenAddrRejectsUnspecifiedAddress(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:7620", "[::]:7620"} {
		if err := validateListenAddr(addr); err == nil {
			t.Fatalf("expected %q to be rejected", addr)
		}
	}
}

func TestValidateListenAddrAcceptsLoopbackAndTailscaleStyleAddresses(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:7620", "100.64.0.1:7620"} {
		if err := validateListenAddr(addr); err != nil {
			t.Fatalf("expected %q to be accepted: %v", addr, err)
		}
	}
}

func TestHTTPServerHasFiniteTimeouts(t *testing.T) {
	server := newHTTPServer("127.0.0.1:0", http.NewServeMux())
	for name, timeout := range map[string]time.Duration{
		"read header": server.ReadHeaderTimeout,
		"read":        server.ReadTimeout,
		"write":       server.WriteTimeout,
		"idle":        server.IdleTimeout,
	} {
		if timeout <= 0 {
			t.Fatalf("%s timeout must be positive", name)
		}
	}
}
