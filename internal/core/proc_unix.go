//go:build linux || darwin

package core

import (
	"os/exec"
	"syscall"
)

func terminate(cmd *exec.Cmd) {
	_ = cmd.Process.Signal(syscall.SIGTERM)
}

func afterStart(*exec.Cmd) error { return nil }
