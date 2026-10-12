// Package sysproxy points the OS proxy settings at the local mixed proxy
// and restores the previous settings afterwards.
//
// The flow is Capture → persist the result → Apply, and Restore later (also
// after a crash, from the persisted state). macOS settings are system-wide
// (networksetup). GNOME/KDE and Windows settings belong to a user: Owner
// names that user, and commands run in their session.
package sysproxy

import (
	"errors"
	"time"
)

// Config is the proxy to set.
type Config struct {
	Host   string
	Port   int
	Bypass []string
}

// DefaultBypass keeps local and private destinations off the proxy.
var DefaultBypass = []string{
	"localhost", "127.0.0.0/8", "::1", "*.local",
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
}

// Owner is the user whose settings change (Linux, Windows). UID < 0 means
// the daemon's own user.
type Owner struct {
	UID int    `json:"uid"`
	SID string `json:"sid,omitempty"`
}

// ErrUnsupported means no supported proxy settings were found, e.g. a
// Linux desktop other than GNOME or KDE.
var ErrUnsupported = errors.New("system proxy is not supported on this desktop; use the TUN mode or set http_proxy/https_proxy/all_proxy (see `beryl env`)")

// cmdTimeout bounds every helper command.
const cmdTimeout = 15 * time.Second
