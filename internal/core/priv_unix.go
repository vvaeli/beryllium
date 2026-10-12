//go:build linux || darwin

package core

import "os"

// privileged reports whether the process may create TUN interfaces.
func privileged() bool { return os.Geteuid() == 0 }
