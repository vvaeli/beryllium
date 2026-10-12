// Package paths resolves OS-specific locations used by the daemon.
package paths

import "path/filepath"

// Paths are the filesystem locations used by the daemon.
type Paths struct {
	// StateDir holds persistent state (subscriptions, settings, daemon.json).
	StateDir string
	// LogDir holds rotated daemon logs.
	LogDir string
	// Socket is the IPC address: a unix socket path or a Windows named pipe.
	Socket string
}

// StateFile returns the path of a file inside StateDir.
func (p Paths) StateFile(name string) string {
	return filepath.Join(p.StateDir, name)
}

// LogFile returns the daemon log file path.
func (p Paths) LogFile() string {
	return filepath.Join(p.LogDir, "daemon.log")
}
