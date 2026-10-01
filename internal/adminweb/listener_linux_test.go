package adminweb

import (
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixPeerRejectsAgentAndArbitraryProcess(t *testing.T) {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "socket"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := trustedPeer(conn); err == nil {
		t.Fatal("agent or arbitrary root process passed as tailscaled")
	}
}

func TestListenerDropsRejectedPeersAndReleasesSlots(t *testing.T) {
	base, err := net.Listen("unix", filepath.Join(t.TempDir(), "socket"))
	if err != nil {
		t.Fatal(err)
	}
	checks := 0
	listener := newPeerListener(base, func(net.Conn) error {
		checks++
		if checks == 1 {
			return errors.New("reject")
		}
		return nil
	})
	defer func() { _ = listener.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	first, err := net.Dial("unix", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := first.Read(make([]byte, 1)); err == nil {
		t.Fatal("rejected peer stayed open")
	}
	second, err := net.Dial("unix", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	select {
	case conn := <-accepted:
		if conn == nil || len(listener.slots) != 1 {
			t.Fatal("trusted peer not accepted or rejected slot leaked")
		}
		_ = conn.Close()
		_ = conn.Close()
		if len(listener.slots) != 0 {
			t.Fatal("connection slot leaked")
		}
	case <-time.After(time.Second):
		t.Fatal("trusted peer never accepted")
	}
}

func TestActivationRequiresExactlyOneSystemdSocket(t *testing.T) {
	t.Setenv("LISTEN_PID", "0")
	t.Setenv("LISTEN_FDS", "1")
	if listener, err := activatedListener(); err == nil || listener != nil {
		t.Fatal("accepted another process's socket")
	}
}

func TestListenerLimitsConnectionsAndUnblocksOnClose(t *testing.T) {
	base, err := net.Listen("unix", filepath.Join(t.TempDir(), "socket"))
	if err != nil {
		t.Fatal(err)
	}
	listener := newPeerListener(base, func(net.Conn) error { return nil })
	defer func() { _ = listener.Close() }()
	accepted := make(chan net.Conn, 9)
	failed := make(chan error, 1)
	go func() {
		for range 9 {
			conn, err := listener.Accept()
			if err != nil {
				failed <- err
				return
			}
			accepted <- conn
		}
	}()
	var connections []net.Conn
	defer func() {
		for _, conn := range connections {
			_ = conn.Close()
		}
	}()
	for range 9 {
		client, err := net.Dial("unix", base.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		connections = append(connections, client)
	}
	for range 8 {
		select {
		case conn := <-accepted:
			connections = append(connections, conn)
		case <-time.After(time.Second):
			t.Fatal("connection was not accepted")
		}
	}
	select {
	case conn := <-accepted:
		_ = conn.Close()
		t.Fatal("more than eight connections accepted")
	case <-time.After(50 * time.Millisecond):
	}
	_ = listener.Close()
	select {
	case err := <-failed:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener close left Accept blocked")
	}
}
