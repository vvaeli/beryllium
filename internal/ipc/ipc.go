// Package ipc provides the daemon's local transport: a unix socket on
// Linux/macOS and a named pipe on Windows, restricted to allowed users.
package ipc

import (
	"errors"
	"log/slog"
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
