package adminweb

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"

	"github.com/R055LE/secrets-broker/internal/securefile"
)

func checkSocket() error {
	info, err := os.Lstat(SocketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || stat.Uid != 0 || stat.Gid != 0 {
		return errors.New("admin socket must be root:root mode 0600")
	}
	return nil
}

func activatedListener() (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" {
		return nil, errors.New("exactly one systemd socket is required")
	}
	if err := checkSocket(); err != nil {
		return nil, err
	}
	file := os.NewFile(3, "systemd-admin-socket")
	defer func() { _ = file.Close() }()
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}
	if listener.Addr().Network() != "unix" || listener.Addr().String() != SocketPath {
		_ = listener.Close()
		return nil, errors.New("systemd supplied an unexpected listener")
	}
	return newPeerListener(listener, trustedPeer), nil
}

func trustedPeer(conn net.Conn) error {
	unix, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("unix peer required")
	}
	raw, err := unix.SyscallConn()
	if err != nil {
		return err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if credErr != nil || cred == nil || cred.Uid != 0 {
		return errors.New("root Serve peer required")
	}
	executable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", cred.Pid))
	if err != nil || executable != "/usr/sbin/tailscaled" {
		return errors.New("tailscaled peer required")
	}
	return securefile.ValidateExecutable(executable)
}

type peerListener struct {
	net.Listener
	check func(net.Conn) error
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

func newPeerListener(listener net.Listener, check func(net.Conn) error) *peerListener {
	return &peerListener{Listener: listener, check: check, slots: make(chan struct{}, 8), done: make(chan struct{})}
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		select {
		case l.slots <- struct{}{}:
		case <-l.done:
			return nil, net.ErrClosed
		}
		conn, err := l.Listener.Accept()
		if err != nil {
			<-l.slots
			return nil, err
		}
		if l.check(conn) != nil {
			_ = conn.Close()
			<-l.slots
			continue
		}
		return &peerConn{Conn: conn, release: func() { <-l.slots }}, nil
	}
}

func (l *peerListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type peerConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *peerConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
