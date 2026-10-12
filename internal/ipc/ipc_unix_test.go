//go:build linux || darwin

package ipc

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Unix socket paths are limited to ~104 bytes, so avoid long t.TempDir paths.
func shortSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "beryl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "d.sock")
}

func TestListenAcceptsSelf(t *testing.T) {
	addr := shortSocket(t)
	ln, err := Listen(addr, Access{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if Authorized(c.RemoteAddr()) {
			c.Write([]byte("ok"))
		} else {
			c.Write([]byte("no"))
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 2)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(buf); err != nil || string(buf) != "ok" {
		t.Fatalf("read = %q, %v", buf, err)
	}
}

func TestAllowedRejectsStrangers(t *testing.T) {
	l := &peerListener{self: 1000, access: Access{UIDs: []uint32{1001}}}
	for uid, want := range map[uint32]bool{0: true, 1000: true, 1001: true, 1002: false} {
		if got := l.allowed(uid, nil); got != want {
			t.Errorf("allowed(%d) = %v, want %v", uid, got, want)
		}
	}
	l.gid, l.hasGid = 500, true
	if !l.allowed(1002, []uint32{500}) {
		t.Error("member of the allowed group was rejected")
	}
}

func TestSecondListenerDetectsRunningDaemon(t *testing.T) {
	addr := shortSocket(t)
	ln, err := Listen(addr, Access{})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	if _, err := Listen(addr, Access{}); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Listen err = %v, want ErrAlreadyRunning", err)
	}
}

func TestStaleSocketIsReplaced(t *testing.T) {
	addr := shortSocket(t)
	if err := os.WriteFile(addr, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ln, err := Listen(addr, Access{})
	if err != nil {
		t.Fatalf("Listen over stale file: %v", err)
	}
	ln.Close()
}

func TestAuthorizedFailsClosed(t *testing.T) {
	if Authorized(&net.UnixAddr{Name: "x", Net: "unix"}) {
		t.Error("plain address was authorized")
	}
	if Authorized(PeerAddr{Allowed: false}) {
		t.Error("disallowed peer was authorized")
	}
	if !Authorized(PeerAddr{Allowed: true}) {
		t.Error("allowed peer was rejected")
	}
}
