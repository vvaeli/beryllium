package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vvaeli/beryllium/internal/core"
)

func TestConnectWorkflow(t *testing.T) {
	bins := core.LoadBinaries(repoCores())
	if !bins.Installed(core.SingBox) {
		t.Skip("cores not fetched; run: go -C tools run ./fetchcores")
	}
	// A local shadowsocks server played by sing-box.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	dir := t.TempDir()
	cfg := fmt.Sprintf(`{"log":{"level":"warn"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":%d,
		"method":"aes-128-gcm","password":"pw"}],"outbounds":[{"type":"direct"}]}`, port)
	os.WriteFile(filepath.Join(dir, "s.json"), []byte(cfg), 0o600)
	srv := exec.Command(bins.Path(core.SingBox), "run", "-c", filepath.Join(dir, "s.json"), "-D", dir)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { srv.Process.Kill(); srv.Wait() }()

	sock := startDaemon(t)
	mustRun := func(args ...string) string {
		t.Helper()
		code, out, errOut := run(append(args, "--socket", sock)...)
		if code != 0 {
			t.Fatalf("beryl %v: exit %d\nstdout:\n%s\nstderr:\n%s", args, code, out, errOut)
		}
		return out
	}
	mustRun("import", fmt.Sprintf("ss://YWVzLTEyOC1nY206cHc@127.0.0.1:%d#Local SS", port))

	// A second, unreachable server for ping.
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadPort := dead.Addr().(*net.TCPAddr).Port
	dead.Close()
	mustRun("import", fmt.Sprintf("ss://YWVzLTEyOC1nY206cHc@127.0.0.1:%d#Dead SS", deadPort))

	out := mustRun("servers")
	if !strings.Contains(out, "LATENCY") {
		t.Fatalf("servers: %s", out)
	}
	pingTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer pingTarget.Close()
	out = mustRun("ping", "--url", pingTarget.URL, "--timeout-per-server", "2s")
	if !strings.Contains(out, " ms  Local SS") || !strings.Contains(out, "fail  Dead SS") || !strings.Contains(out, "1/2 responded") {
		t.Fatalf("http ping: %s", out)
	}
	out = mustRun("ping", "--method", "tcp")
	if !strings.Contains(out, " ms  Local SS") || !strings.Contains(out, "fail  Dead SS") || !strings.Contains(out, "fastest: Local SS") {
		t.Fatalf("tcp ping: %s", out)
	}
	if out = mustRun("ping", "local", "--method", "icmp"); !strings.Contains(out, " ms  Local SS") && !strings.Contains(out, "not permitted") {
		t.Fatalf("icmp ping: %s", out)
	}
	// Only HTTP results feed the latency column: refresh it after tcp/icmp.
	mustRun("ping", "--url", pingTarget.URL, "--timeout-per-server", "2s")
	out = mustRun("servers", "--sort", "latency")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.Contains(lines[1], "Local SS") || !strings.HasSuffix(strings.TrimSpace(lines[2]), "fail") {
		t.Fatalf("servers --sort latency:\n%s", out)
	}
	mustRun("sub", "rm", "Dead SS")

	out = mustRun("connect", "local ss")
	if !strings.Contains(out, "connected") || !strings.Contains(out, "sing-box") || !strings.Contains(out, "proxy:    127.0.0.1:") {
		t.Fatalf("connect: %s", out)
	}
	var st struct {
		LocalProxy string `json:"local_proxy"`
	}
	json.Unmarshal([]byte(mustRun("status", "--json")), &st)
	if st.LocalProxy == "" {
		t.Fatal("status --json has no local_proxy")
	}

	// The tunnel reaches a target served on loopback.
	target, _ := net.Listen("tcp", "127.0.0.1:0")
	defer target.Close()
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
			c.Close()
		}
	}()
	if out = mustRun("test", "http://"+target.Addr().String()+"/"); !strings.HasPrefix(out, "ok, ") {
		t.Fatalf("test: %s", out)
	}

	code, _, errOut := run("connect", "local ss", "--core", "mihomo", "--socket", sock)
	if code != 1 || !strings.Contains(errOut, "mihomo") {
		t.Fatalf("connect with incapable core: exit %d %s", code, errOut)
	}

	if out = mustRun("disconnect"); !strings.Contains(out, "disconnected") {
		t.Fatalf("disconnect: %s", out)
	}
	if out = mustRun("version"); !strings.Contains(out, "sing-box  1.") || !strings.Contains(out, "mihomo") {
		t.Fatalf("version: %s", out)
	}
}
