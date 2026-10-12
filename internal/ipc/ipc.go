// Package ipc provides the daemon's local transport: a unix socket on
// Linux/macOS and a named pipe on Windows, restricted to allowed users.
package ipc

import (
	"errors"
	"log/slog"
	"net"
)

// ErrAlreadyRunning is returned by Listen when another daemon already
// serves the address.
var ErrAlreadyRunning = errors.New("ipc: another daemon is already listening")

// Access lists who may connect besides root/SYSTEM/Administrators and the
// daemon's own user, which are always allowed.
type Access struct {
	// UIDs of allowed users (Linux, macOS).
	UIDs []uint32
	// Group whose members may connect (Linux). Ignored if it doesn't exist.
	Group string
	// SIDs of allowed users (Windows).
	SIDs []string
	// Logger receives rejected-connection warnings (unix). Defaults to slog.Default().
	Logger *slog.Logger
}

// PeerAddr is the RemoteAddr of every connection returned by a Listen
// listener. It carries the verified peer identity so the API layer can
// answer unauthorized peers with a proper error instead of a dropped
// connection.
type PeerAddr struct {
	net.Addr
	// UID of the peer (Linux, macOS).
	UID uint32
	// Allowed is the access decision for this peer.
	Allowed bool
}

// Authorized reports whether a connection whose RemoteAddr is a may use the
// API. It fails closed: addresses not produced by Listen are rejected.
func Authorized(a net.Addr) bool {
	p, ok := a.(PeerAddr)
	return ok && p.Allowed
}

type peerConn struct {
	net.Conn
	peer PeerAddr
}

func (c peerConn) RemoteAddr() net.Addr { return c.peer }
