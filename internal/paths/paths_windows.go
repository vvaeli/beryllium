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
	cores := filepath.Join(dir, "cores")
	if exe, err := os.Executable(); err == nil {
		cores = filepath.Join(filepath.Dir(exe), "cores")
	}
	return Paths{
		CoresDir: cores,
		StateDir: dir,
		LogDir:   filepath.Join(dir, "logs"),
		Socket:   `\\.\pipe\beryllium`,
	}
}
