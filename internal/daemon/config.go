package daemon

import (
	"github.com/vvaeli/beryllium/internal/paths"
	"github.com/vvaeli/beryllium/internal/store"
)

// Config is daemon-level configuration written at install time
// (daemon.json in the state dir). User-facing settings live elsewhere.
type Config struct {
	// AllowedUIDs may use the IPC socket (Linux, macOS). Recorded from
	// SUDO_UID by `berylliumd install`.
	AllowedUIDs []uint32 `json:"allowed_uids,omitempty"`
	// AllowedSIDs may use the IPC pipe (Windows).
	AllowedSIDs []string `json:"allowed_sids,omitempty"`
}

// ConfigStore returns the store for daemon.json.
func ConfigStore(p paths.Paths) *store.Store[Config] {
	return store.Open[Config](p.StateFile("daemon.json"))
}
