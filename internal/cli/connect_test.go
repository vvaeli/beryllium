package cli

import (
	"encoding/json"
	"fmt"
	"net"
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
			t.Fatalf("beryl %v: exit %d\n%s%s", args, code, out, errOut)
		}
		return out
	}
	mustRun("import", fmt.Sprintf("ss://YWVzLTEyOC1nY206cHc@127.0.0.1:%d#Local SS", port))

	out := mustRun("connect", "local ss")
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
