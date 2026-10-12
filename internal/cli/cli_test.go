package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/client"
	"github.com/vvaeli/beryllium/internal/daemon"
	"github.com/vvaeli/beryllium/internal/paths"
	"github.com/vvaeli/beryllium/internal/watchdog"
	"google.golang.org/grpc"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func startDaemon(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "beryl") // short: unix socket path limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	if runtime.GOOS == "windows" {
		sock = fmt.Sprintf(`\\.\pipe\beryllium-cli-test-%d`, time.Now().UnixNano())
	}
	// The daemon and core logs are printed when the test fails.
	logs := &syncBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("daemon log:\n%s", logs.String())
		}
	})
	// The watchdog checks the tunnel against a loopback target instead of
	// public endpoints, and the network counts as up.
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	t.Cleanup(probe.Close)
	d := daemon.New(daemon.Options{
		Paths:          paths.Paths{StateDir: filepath.Join(dir, "state"), LogDir: dir, Socket: sock, CoresDir: repoCores()},
		Log:            slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		CoreLogLevel:   "debug",
		ProbeURLs:      []string{probe.URL},
		Reach:          func(context.Context) watchdog.Reach { return watchdog.Online },
		NoSystemEvents: true,
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	c, err := client.New(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer rcancel()
	if _, err := c.Daemon.Health(rctx, &berylliumv1.HealthRequest{}, grpc.WaitForReady(true)); err != nil {
		t.Fatal(err)
	}
	return sock
}

func repoCores() string {
	dir, _ := filepath.Abs(filepath.Join("..", "..", "cores", "bin", runtime.GOOS+"-"+runtime.GOARCH))
	return dir
}

func run(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = Run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVersionJSON(t *testing.T) {
	sock := startDaemon(t)
	code, out, errOut := run("version", "--json", "--socket", sock)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errOut)
	}
	var v struct {
		CLI    map[string]string `json:"cli"`
		Daemon struct {
			Version string `json:"version"`
			OS      string `json:"os"`
		} `json:"daemon"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("invalid JSON %q: %v", out, err)
	}
	if v.CLI["version"] == "" || v.Daemon.OS != runtime.GOOS {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestVersionHuman(t *testing.T) {
	sock := startDaemon(t)
	_, out, _ := run("version", "--socket", sock)
	if !strings.Contains(out, "berylliumd  dev") {
		t.Fatalf("daemon version missing:\n%s", out)
	}
}

func TestVersionWithoutDaemon(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "none.sock")
	if runtime.GOOS == "windows" {
		sock = `\\.\pipe\beryllium-cli-missing`
	}
	code, out, errOut := run("version", "--socket", sock, "--timeout", "2s")
	if code != 0 {
		t.Fatalf("exit %d; version must work without a daemon", code)
	}
	if !strings.Contains(out, "not running") || !strings.Contains(errOut, "hint:") {
		t.Fatalf("missing explanation:\nstdout: %s\nstderr: %s", out, errOut)
	}
}

func TestUnknownCommand(t *testing.T) {
	if code, _, errOut := run("nope"); code != 1 || !strings.Contains(errOut, "unknown command") {
		t.Fatalf("exit %d, stderr: %s", code, errOut)
	}
}
