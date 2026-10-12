//go:build linux || darwin

package sysproxy

import (
	"context"
	"errors"
	"os/exec"
	"strings"
)

// runner executes a command and returns its trimmed stdout. Replaced in tests.
type runner func(ctx context.Context, o Owner, name string, args ...string) (string, error)

var run runner = execRun

func execRun(ctx context.Context, o Owner, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	if err := asUser(cmd, o); err != nil {
		return "", err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(string(out))
		}
		if msg != "" {
			return "", errors.New(name + ": " + msg)
		}
		return "", errors.New(name + ": " + err.Error())
	}
	return strings.TrimSpace(string(out)), nil
}
