package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vvaeli/beryllium/internal/model"
)

func collect(t *testing.T, p *Pinger, servers []model.Server, o PingOptions) map[string]PingResult {
	t.Helper()
	out := make(chan PingResult, len(servers))
	done := make(chan struct{})
	got := map[string]PingResult{}
	go func() {
		for r := range out {
			got[r.ServerID] = r
		}
		close(done)
	}()
	p.Ping(context.Background(), servers, o, out)
	close(out)
	<-done
	if len(got) != len(servers) {
		t.Fatalf("got %d results for %d servers", len(got), len(servers))
	}
	return got
}

func TestPingHTTPBatch(t *testing.T) {
	bins := testBinaries(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer target.Close()
	cert, key := selfSignedCert(t)

	ssPort, _ := freePort()
	startServer(t, bins, SingBox, map[string]any{
		"inbounds":  []any{map[string]any{"type": "shadowsocks", "listen": "127.0.0.1", "listen_port": ssPort, "method": "aes-128-gcm", "password": "pw"}},
		"outbounds": []any{map[string]any{"type": "direct"}},
	})
	xhPort, _ := freePort()
	startServer(t, bins, Xray, map[string]any{
		"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": xhPort, "protocol": "vless",
			"settings":       map[string]any{"clients": []any{map[string]any{"id": tUUID}}, "decryption": "none"},
			"streamSettings": map[string]any{"network": "xhttp", "xhttpSettings": map[string]any{"path": "/x"}}}},
		"outbounds": []any{map[string]any{"protocol": "freedom"}},
	})
	hyPort, _ := freePort()
	startServer(t, bins, SingBox, map[string]any{
		"inbounds": []any{map[string]any{"type": "hysteria2", "listen": "127.0.0.1", "listen_port": hyPort,
			"users": []any{map[string]any{"password": "pw"}},
			"tls":   map[string]any{"enabled": true, "certificate_path": cert, "key_path": key}}},
		"outbounds": []any{map[string]any{"type": "direct"}},
	})
	deadPort, _ := freePort()
	time.Sleep(500 * time.Millisecond) // let the test servers bind

	servers := []model.Server{
		{ID: "ss", Protocol: model.Shadowsocks, Address: "127.0.0.1", Port: uint16(ssPort), Method: "aes-128-gcm", Password: "pw"},
		{ID: "xhttp", Protocol: model.VLESS, Address: "127.0.0.1", Port: uint16(xhPort), UUID: tUUID,
			Transport: &model.Transport{Type: "xhttp", Path: "/x"}},
		// Certificate pinning routes this one through mihomo.
		{ID: "hy2-mihomo", Protocol: model.Hysteria2, Address: "127.0.0.1", Port: uint16(hyPort), Password: "pw",
			TLS: &model.TLS{Security: "tls", SNI: "localhost", PinSHA256: certSHA256(t, cert)}},
		{ID: "dead", Protocol: model.Shadowsocks, Address: "127.0.0.1", Port: uint16(deadPort), Method: "aes-128-gcm", Password: "pw"},
		{ID: "wrong-pass", Protocol: model.Shadowsocks, Address: "127.0.0.1", Port: uint16(ssPort), Method: "aes-128-gcm", Password: "nope"},
		{ID: "awg-dead", Protocol: model.AmneziaWG, Address: "127.0.0.1", Port: uint16(deadPort),
			WireGuard: &model.WireGuardOpts{PrivateKey: tWGPriv, PublicKey: tWGPub, Addresses: []string{"10.0.0.2/32"},
				Amnezia: map[string]string{"jc": "4"}}},
	}
	if c, _ := Choose(&servers[2], "", nil); c.Kind != Mihomo {
		t.Fatalf("pinned hy2 should use mihomo, got %s", c.Kind)
	}
	p := &Pinger{Binaries: bins, WorkDir: t.TempDir()}
	got := collect(t, p, servers, PingOptions{URL: target.URL, Timeout: 3 * time.Second})

	for _, id := range []string{"ss", "xhttp", "hy2-mihomo"} {
		r := got[id]
		if r.Err != nil || r.Latency <= 0 {
			t.Errorf("%s: %+v", id, r)
		}
		// Loopback round trips take milliseconds; anything near a second
		// means the measurement adds its own overhead (as sing-box's Clash
		// API delay test did).
		if r.Latency > 500*time.Millisecond {
			t.Errorf("%s: loopback latency %v is implausibly high", id, r.Latency)
		}
	}
	for _, id := range []string{"dead", "wrong-pass", "awg-dead"} {
		if r := got[id]; r.Err == nil {
			t.Errorf("%s: expected an error, got %v", id, r.Latency)
		}
	}
}

func certSHA256(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

func TestPingTCP(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	dead, _ := freePort()
	servers := []model.Server{
		{ID: "up", Protocol: model.Trojan, Address: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port)},
		{ID: "down", Protocol: model.Trojan, Address: "127.0.0.1", Port: uint16(dead)},
		{ID: "udp", Protocol: model.Hysteria2, Address: "127.0.0.1", Port: 443},
	}
	got := collect(t, &Pinger{}, servers, PingOptions{Method: PingTCP, Timeout: 2 * time.Second})
	if got["up"].Err != nil || got["up"].Latency <= 0 {
		t.Errorf("up: %+v", got["up"])
	}
	if got["down"].Err == nil {
		t.Error("down: no error")
	}
	if e := got["udp"].Err; e == nil || !strings.Contains(e.Error(), "UDP") {
		t.Errorf("udp: %v", e)
	}
}

func TestPingICMP(t *testing.T) {
	got := collect(t, &Pinger{}, []model.Server{{ID: "lo", Address: "127.0.0.1"}}, PingOptions{Method: PingICMP, Timeout: 2 * time.Second})
	r := got["lo"]
	if r.Err != nil && strings.Contains(r.Err.Error(), "not permitted") {
		t.Skipf("ICMP sockets unavailable here: %v", r.Err)
	}
	if r.Err != nil || r.Latency <= 0 {
		t.Fatalf("lo: %+v", r)
	}
}
