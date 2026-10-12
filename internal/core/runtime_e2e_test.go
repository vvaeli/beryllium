package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/vvaeli/beryllium/internal/model"
)

// startServer runs a core as a proxy *server* for the test, from cfg.
func startServer(t *testing.T, bins *Binaries, k Kind, cfg any) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "server.json")
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"run", "-c", file}
	if k == SingBox {
		args = append(args, "-D", dir)
	}
	cmd := exec.Command(bins.Path(k), args...)
	cmd.Dir = dir
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
}

func selfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return certPath, keyPath
}

func newTestRuntime(t *testing.T, bins *Binaries) *Runtime {
	t.Helper()
	port, _ := freePort()
	r := New(Options{Binaries: bins, WorkDir: t.TempDir(), MixedPort: port,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	t.Cleanup(r.Close)
	return r
}

// getThrough fetches target via the runtime's local proxy, retrying briefly
// while the test server finishes starting.
func getThrough(t *testing.T, r *Runtime, target string) string {
	t.Helper()
	proxy, _ := url.Parse("http://" + r.Status().LocalProxy)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}, Timeout: 5 * time.Second}
	var lastErr error
	for i := 0; i < 30; i++ {
		resp, err := client.Get(target)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return string(body)
			}
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("request through proxy failed: %v", lastErr)
	return ""
}

func TestRuntimeEndToEnd(t *testing.T) {
	bins := testBinaries(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("hello through the tunnel"))
	}))
	defer target.Close()
	cert, key := selfSignedCert(t)

	ssPort, _ := freePort()
	startServer(t, bins, SingBox, map[string]any{
		"log":       map[string]any{"level": "warn"},
		"inbounds":  []any{map[string]any{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": ssPort, "method": "aes-128-gcm", "password": "pw"}},
		"outbounds": []any{map[string]any{"type": "direct"}},
	})
	xhPort, _ := freePort()
	startServer(t, bins, Xray, map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": xhPort, "protocol": "vless",
			"settings":       map[string]any{"clients": []any{map[string]any{"id": tUUID}}, "decryption": "none"},
			"streamSettings": map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/x"}}}},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
	})
	hyPort, _ := freePort()
	startServer(t, bins, SingBox, map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{"type": "hysteria2", "listen": "127.0.0.1", "listen_port": hyPort,
			"users": []any{map[string]any{"password": "pw"}},
			"tls":   map[string]any{"enabled": true, "certificate_path": cert, "key_path": key}}},
		"outbounds": []any{map[string]any{"type": "direct"}},
	})

	hy2 := model.Server{Name: "hy2", Protocol: model.Hysteria2, Address: "127.0.0.1", Port: uint16(hyPort), Password: "pw",
		TLS: &model.TLS{Security: "tls", SNI: "localhost", Insecure: true}}
	cases := []struct {
		name     string
		srv      model.Server
		override Kind
		wantCore Kind
	}{
		{"shadowsocks via sing-box", model.Server{Name: "ss", Protocol: model.Shadowsocks, Address: "127.0.0.1",
			Port: uint16(ssPort), Method: "aes-128-gcm", Password: "pw"}, "", SingBox},
		{"vless xhttp via xray chain", model.Server{Name: "xh", Protocol: model.VLESS, Address: "127.0.0.1",
			Port: uint16(xhPort), UUID: tUUID, Transport: &model.Transport{Type: "xhttp", Path: "/x"}}, "", Xray},
		{"hysteria2 via sing-box", hy2, "", SingBox},
		{"hysteria2 via mihomo chain", hy2, Mihomo, Mihomo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRuntime(t, bins)
			st, err := r.Connect(context.Background(), tc.srv, tc.override)
			if err != nil {
				t.Fatalf("Connect: %v", err)
			}
			if st.Core != tc.wantCore || st.State != StateConnected {
				t.Fatalf("status = %+v", st)
			}
			if got := getThrough(t, r, target.URL); got != "hello through the tunnel" {
				t.Fatalf("body = %q", got)
			}
			if lat, err := r.URLTest(context.Background(), target.URL); err != nil || lat <= 0 {
				t.Fatalf("URLTest = %v, %v", lat, err)
			}
			tr, err := r.Traffic(context.Background())
			if err != nil || tr.Download == 0 {
				t.Fatalf("Traffic = %+v, %v", tr, err)
			}
			if st := r.Disconnect(); st.State != StateDisconnected {
				t.Fatalf("after disconnect: %+v", st)
			}
		})
	}

	t.Run("recovers after a core crash", func(t *testing.T) {
		r := newTestRuntime(t, bins)
		ss := cases[0].srv
		if _, err := r.Connect(context.Background(), ss, ""); err != nil {
			t.Fatal(err)
		}
		r.mu.Lock()
		victim := r.sess.procs[0]
		r.mu.Unlock()
		_ = victim.cmd.Process.Kill()

		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if st := r.Status(); st.State == StateConnected && st.Restarts == 1 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if st := r.Status(); st.Restarts != 1 || st.State != StateConnected {
			t.Fatalf("status after crash = %+v", st)
		}
		if got := getThrough(t, r, target.URL); got != "hello through the tunnel" {
			t.Fatalf("after restart body = %q", got)
		}
	})

	// Like `berylliumd -config-dir .dev/state -cores-dir cores/bin/...`.
	t.Run("relative cores and work dirs", func(t *testing.T) {
		wd := mustGetwd(t)
		relCores, err := filepath.Rel(wd, bins.Dir)
		if err != nil {
			t.Fatal(err)
		}
		work, err := os.MkdirTemp(wd, ".test-work-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(work) })
		port, _ := freePort()
		r := New(Options{Binaries: LoadBinaries(relCores), WorkDir: filepath.Base(work), MixedPort: port,
			Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
		t.Cleanup(r.Close)
		if _, err := r.Connect(context.Background(), cases[0].srv, ""); err != nil {
			t.Fatalf("Connect with relative dirs: %v", err)
		}
		if got := getThrough(t, r, target.URL); got != "hello through the tunnel" {
			t.Fatalf("body = %q", got)
		}
	})

	t.Run("startup failure is reported", func(t *testing.T) {
		r := newTestRuntime(t, bins)
		bad := model.Server{Protocol: model.VLESS, Address: "127.0.0.1", Port: 1, UUID: "x",
			Transport: &model.Transport{Type: "xhttp", Extra: "{not json"}}
		if _, err := r.Connect(context.Background(), bad, ""); err == nil || r.Status().State != StateFailed {
			t.Fatalf("Connect(bad) err=%v status=%+v", err, r.Status())
		}
	})
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}
