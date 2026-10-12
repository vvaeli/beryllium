package daemon

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	berylliumv1 "github.com/vvaeli/beryllium/gen/go/beryllium/v1"
	"github.com/vvaeli/beryllium/internal/ipc"
	"github.com/vvaeli/beryllium/internal/paths"
	"github.com/vvaeli/beryllium/internal/version"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func testPaths(t *testing.T) paths.Paths {
	t.Helper()
	// Short dir: unix socket paths are limited to ~104 bytes.
	dir, err := os.MkdirTemp("", "beryl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	if runtime.GOOS == "windows" {
		sock = fmt.Sprintf(`\\.\pipe\beryllium-test-%d`, time.Now().UnixNano())
	}
	return paths.Paths{StateDir: filepath.Join(dir, "state"), LogDir: dir, Socket: sock}
}

func dial(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///beryllium",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return ipc.Dial(ctx, addr)
		}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestDaemonLifecycle(t *testing.T) {
	p := testPaths(t)
	d := New(p, slog.New(slog.NewTextHandler(io.Discard, nil)))

	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(context.Background()) }()

	conn := dial(t, p.Socket)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := berylliumv1.NewDaemonServiceClient(conn)

	// The listener may not be up yet; wait for readiness.
	ver, err := client.GetVersion(ctx, &berylliumv1.GetVersionRequest{}, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("GetVersion: %v", err)
	}
	if ver.GetVersion() != version.Version || ver.GetOs() != runtime.GOOS {
		t.Errorf("GetVersion = %v", ver)
	}

	h, err := client.Health(ctx, &berylliumv1.HealthRequest{})
	if err != nil || !h.GetOk() {
		t.Fatalf("Health = %v, %v", h, err)
	}

	_, err = berylliumv1.NewSubscriptionServiceClient(conn).ListSubscriptions(ctx, &berylliumv1.ListSubscriptionsRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Errorf("ListSubscriptions err = %v, want Unimplemented", err)
	}

	if _, err := client.Shutdown(ctx, &berylliumv1.ShutdownRequest{}); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not stop after Shutdown")
	}

	if runtime.GOOS != "windows" {
		if _, err := os.Stat(p.Socket); !os.IsNotExist(err) {
			t.Errorf("socket not removed after shutdown: %v", err)
		}
	}
}

func TestDaemonStopsOnContextCancel(t *testing.T) {
	p := testPaths(t)
	d := New(p, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run(ctx) }()

	conn := dial(t, p.Socket)
	rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer rcancel()
	if _, err := berylliumv1.NewDaemonServiceClient(conn).Health(rctx, &berylliumv1.HealthRequest{}, grpc.WaitForReady(true)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not stop after cancel")
	}
}
