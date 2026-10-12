//go:build linux || darwin

package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// killOrphans kills core processes left by a previous daemon instance,
// verifying the executable name so a reused PID is never touched.
func killOrphans(pids map[int]string) {
	for pid, path := range pids {
		out, err := exec.Command("ps", "-o", "comm=", "-p", strconv.Itoa(pid)).Output()
		if err != nil {
			continue
		}
		if filepath.Base(strings.TrimSpace(string(out))) != filepath.Base(path) {
			continue
		}
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Signal(syscall.SIGKILL)
		}
	}
}
