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
	"runtime"
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
	// ICMP sockets may be forbidden (e.g. Linux CI without ping_group_range);
	// then the command reports it and exits 1.
	code, out, _ := run("ping", "local", "--method", "icmp", "--socket", sock)
	replied := code == 0 && strings.Contains(out, " ms  Local SS")
	forbidden := code == 1 && strings.Contains(out, "not permitted")
	if !replied && !forbidden {
		t.Fatalf("icmp ping: exit %d %s", code, out)
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
	url := "http://" + target.Addr().String() + "/"
	host := target.Addr().(*net.TCPAddr).IP.String()
	testOK := func(step string) {
		t.Helper()
		if code, out, errOut := run("test", url, "--socket", sock); code != 0 || !strings.HasPrefix(out, "ok, ") {
			t.Fatalf("test (%s): exit %d %s%s", step, code, out, errOut)
		}
	}
	// Private addresses go direct by default; a user rule sends this one
	// through the tunnel (front → shadowsocks server → target).
	mustRun("rules", "add", "ip", host, "proxy")
	testOK("through the tunnel")
	// Rules apply live: block the target.
	mustRun("rules", "rm", "1")
	if out = mustRun("rules", "add", "ip", host, "block"); !strings.Contains(out, "ip-cidr") || !strings.Contains(out, host) {
		t.Fatalf("rules add: %s", out)
	}
	if code, out, _ := run("test", url, "--socket", sock); code == 0 {
		t.Fatalf("test passed through a block rule: %s", out)
	}
	if out = mustRun("rules", "rm", "1"); !strings.Contains(out, "no rules") {
		t.Fatalf("rules rm: %s", out)
	}
	testOK("LAN direct")

	// Routing profiles: builtins, import, activate, share, remove.
	if out = mustRun("routing"); !strings.Contains(out, "* ") || !strings.Contains(out, "Proxy everything") || !strings.Contains(out, "Russia direct") {
		t.Fatalf("routing ls: %s", out)
	}
	prof := filepath.Join(t.TempDir(), "p.json")
	os.WriteFile(prof, []byte(`{"Name":"Test Profile","GlobalProxy":"false","ProxySites":["domain:example.org"],"BlockIp":["198.51.100.0/24"]}`), 0o600)
	if out = mustRun("routing", "import", prof); !strings.Contains(out, "Test Profile") || !strings.Contains(out, "active") {
		t.Fatalf("routing import: %s", out)
	}
	if out = mustRun("status"); !strings.Contains(out, "connected") {
		t.Fatalf("status after profile switch: %s", out)
	}
	if out = mustRun("routing", "share", "test profile"); !strings.HasPrefix(out, "happ://routing/onadd/") {
		t.Fatalf("routing share: %s", out)
	}
	mustRun("routing", "use", "proxy everything")
	mustRun("routing", "rm", "test profile")
	if out = mustRun("routing"); strings.Contains(out, "Test Profile") {
		t.Fatalf("profile not removed: %s", out)
	}

	if out = mustRun("dns", "--ipv6", "tunnel", "--remote", "tls://9.9.9.9"); !strings.Contains(out, "ipv6:     tunnel") || !strings.Contains(out, "tls://9.9.9.9") {
		t.Fatalf("dns: %s", out)
	}
	if code, _, errOut := run("dns", "--remote", "sdns://x", "--socket", sock); code != 1 || !strings.Contains(errOut, "remote DNS") {
		t.Fatalf("bad resolver accepted: %s", errOut)
	}
	if out = mustRun("env", "--shell", "fish"); !strings.Contains(out, "set -gx http_proxy \"http://127.0.0.1:") {
		t.Fatalf("env: %s", out)
	}
	if out = mustRun("mode"); strings.TrimSpace(out) != "local" {
		t.Fatalf("mode: %s", out)
	}
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		code, _, errOut := run("connect", "local ss", "--mode", "tun", "--socket", sock)
		if code != 1 || !strings.Contains(errOut, "root") {
			t.Fatalf("tun without root: exit %d %s", code, errOut)
		}
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
