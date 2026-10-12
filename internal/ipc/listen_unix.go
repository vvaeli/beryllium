//go:build linux || darwin

package ipc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"time"
)

// Listen creates the unix socket at addr. Peers are identified on Accept
// using kernel-provided credentials, and the decision is exposed through
// PeerAddr (see Authorized).
func Listen(addr string, a Access) (net.Listener, error) {
	// sun_path is 104 bytes on macOS and 108 on Linux, including the NUL.
	if len(addr) >= 104 {
		return nil, fmt.Errorf("ipc: socket path is %d bytes, must be under 104: %s", len(addr), addr)
	}
	if err := os.MkdirAll(filepath.Dir(addr), 0o755); err != nil {
		return nil, err
	}
	if _, err := os.Stat(addr); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, err := Dial(ctx, addr)
		cancel()
		if err == nil {
			c.Close()
			return nil, ErrAlreadyRunning
		}
		if err := os.Remove(addr); err != nil {
			return nil, fmt.Errorf("ipc: remove stale socket: %w", err)
		}
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: addr, Net: "unix"})
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(true)

	pl := &peerListener{UnixListener: ln, access: a, self: uint32(os.Geteuid())}
	// Peer credentials are the real gate. File permissions are defense in
	// depth: root:<group> 0660 when the group exists, otherwise world-connectable.
	mode := os.FileMode(0o666)
	if a.Group != "" {
		if g, err := user.LookupGroup(a.Group); err == nil {
			gid, _ := strconv.ParseUint(g.Gid, 10, 32)
			pl.gid = uint32(gid)
			pl.hasGid = true
			if os.Geteuid() == 0 {
				if err := os.Chown(addr, 0, int(gid)); err == nil {
					mode = 0o660
				}
			}
		}
	}
	if err := os.Chmod(addr, mode); err != nil {
		ln.Close()
		return nil, err
	}
	return pl, nil
}

// Dial connects to the daemon socket.
func Dial(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", addr)
}

type peerListener struct {
	*net.UnixListener
	access Access
	self   uint32
	gid    uint32
	hasGid bool
}

func (l *peerListener) Accept() (net.Conn, error) {
	c, err := l.AcceptUnix()
	if err != nil {
		return nil, err
	}
	uid, gids, err := peerCred(c)
	allowed := err == nil && l.allowed(uid, gids)
	switch {
	case err != nil:
		l.access.logger().Warn("ipc: can't identify peer", "err", err)
	case !allowed:
		l.access.logger().Warn("ipc: unauthorized peer", "uid", uid)
	}
	return peerConn{Conn: c, peer: PeerAddr{Addr: c.RemoteAddr(), UID: uid, Allowed: allowed}}, nil
}

func (l *peerListener) allowed(uid uint32, gids []uint32) bool {
	if uid == 0 || uid == l.self || slices.Contains(l.access.UIDs, uid) {
		return true
	}
	if !l.hasGid {
		return false
	}
	if slices.Contains(gids, l.gid) {
		return true
	}
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return false
	}
	ids, err := u.GroupIds()
	return err == nil && slices.Contains(ids, strconv.FormatUint(uint64(l.gid), 10))
}

func peerCred(c *net.UnixConn) (uid uint32, gids []uint32, err error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, nil, err
	}
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		uid, gids, credErr = sockPeerCred(int(fd))
	}); err != nil {
		return 0, nil, err
	}
	if credErr != nil {
		return 0, nil, errors.Join(errors.New("ipc: read peer credentials"), credErr)
	}
	return uid, gids, nil
}

func (a Access) logger() *slog.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return slog.Default()
}
