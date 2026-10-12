// Package core runs proxy cores (sing-box, Xray, mihomo) as supervised
// subprocesses and translates model.Server into their configs.
//
// sing-box always fronts the chain: it owns the local mixed (HTTP+SOCKS5)
// inbound (and TUN later) and either connects to the server itself or
// forwards to Xray/mihomo over a loopback SOCKS port.
package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Kind identifies a core.
type Kind string

// Supported cores, in default preference order.
const (
	SingBox Kind = "sing-box"
	Xray    Kind = "xray"
	Mihomo  Kind = "mihomo"
)

// Kinds lists all cores in preference order.
var Kinds = []Kind{SingBox, Xray, Mihomo}

// ParseKind accepts core names as shown to users.
func ParseKind(s string) (Kind, error) {
	switch s {
	case "sing-box", "singbox", "sing_box":
		return SingBox, nil
	case "xray":
		return Xray, nil
	case "mihomo", "clash", "clash-meta":
		return Mihomo, nil
	}
	return "", fmt.Errorf("unknown core %q (want sing-box, xray or mihomo)", s)
}

// Binaries locates installed core executables.
type Binaries struct {
	Dir      string
	versions map[Kind]string
}

// manifest.json is written by tools/fetchcores next to the binaries.
type manifestEntry struct {
	Version string `json:"version"`
	File    string `json:"file"`
	SHA256  string `json:"sha256"`
}

// LoadBinaries reads dir. A missing manifest only means unknown versions.
func LoadBinaries(dir string) *Binaries {
	b := &Binaries{Dir: dir, versions: map[Kind]string{}}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return b
	}
	var m map[string]manifestEntry
	if json.Unmarshal(raw, &m) == nil {
		for k, e := range m {
			b.versions[Kind(k)] = e.Version
		}
	}
	return b
}

// Path returns the executable path for k.
func (b *Binaries) Path(k Kind) string {
	name := string(k)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(b.Dir, name)
}

// Installed reports whether k's executable exists.
func (b *Binaries) Installed(k Kind) bool {
	fi, err := os.Stat(b.Path(k))
	return err == nil && fi.Mode().IsRegular()
}

// Version returns k's version from the manifest, or "".
func (b *Binaries) Version(k Kind) string {
	return b.versions[k]
}

// ErrNotInstalled is returned when a required core binary is missing.
var ErrNotInstalled = errors.New("core is not installed")
