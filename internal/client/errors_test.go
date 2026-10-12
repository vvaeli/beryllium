package client

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestExplainNotRunning(t *testing.T) {
	addr := filepath.Join(t.TempDir(), "missing.sock")
	if runtime.GOOS == "windows" {
		addr = `\\.\pipe\beryllium-missing-test`
	}
	c, err := New(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = c.Daemon.Health(ctx, &berylliumv1.HealthRequest{})
	var e *Error
	if !errors.As(c.Explain(err), &e) || !strings.Contains(e.Msg, "not running") || e.Hint == "" {
		t.Fatalf("Explain(%v) = %#v, want not-running error with hint", err, e)
	}
}

func TestExplainPermissionDenied(t *testing.T) {
	c := &Client{addr: os.DevNull}
	var e *Error
	err := c.Explain(status.Error(codes.PermissionDenied, "no"))
	if !errors.As(err, &e) || e.Hint == "" {
		t.Fatalf("Explain(PermissionDenied) = %v, want *Error with hint", err)
	}
}
