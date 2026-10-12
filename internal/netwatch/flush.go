package netwatch

import (
	"context"
	"os/exec"
	"runtime"
	"time"
)

// FlushDNS clears the OS DNS cache, so names cached on the previous
// network aren't reused (ROADMAP 7.11). Failures are ignored: the cache
// may not exist (no systemd-resolved) or we may lack privileges.
func FlushDNS(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var cmds [][]string
	switch runtime.GOOS {
	case "darwin":
		cmds = [][]string{{"dscacheutil", "-flushcache"}, {"killall", "-HUP", "mDNSResponder"}}
	case "linux":
		cmds = [][]string{{"resolvectl", "flush-caches"}}
	case "windows":
		cmds = [][]string{{"ipconfig", "/flushdns"}}
	}
	for _, c := range cmds {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		_ = exec.CommandContext(ctx, c[0], c[1:]...).Run()
	}
}
