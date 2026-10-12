package core

import (
	"os/exec"
	"syscall"
)

// Cores die with the daemon even if it is SIGKILLed.
func setProcAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
