package core

import "os/exec"

// macOS has no parent-death signal; orphans from a crashed daemon are
// killed on the next start via the pid file (see orphans_unix.go).
func setProcAttrs(*exec.Cmd) {}
