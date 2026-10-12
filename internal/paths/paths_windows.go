package paths

import (
	"os"
	"path/filepath"
)

// Default returns the system-wide locations for a daemon run as a Windows service.
func Default() Paths {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	dir := filepath.Join(base, "Beryllium")
	return Paths{
		StateDir: dir,
		LogDir:   filepath.Join(dir, "logs"),
		Socket:   `\\.\pipe\beryllium`,
	}
}
