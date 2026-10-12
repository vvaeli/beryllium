package cli

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const panelBody = "vless://0b6e9f2c-1a2b-4c3d-8e9f-0123456789ab@1.2.3.4:443?security=reality&sni=a.com&pbk=K&sid=1&type=tcp#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam\n" +
	"hy2://pw@h.example.com:443?sni=h.example.com#Helsinki\n"

func TestSubscriptionWorkflow(t *testing.T) {
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Profile-Title", "Test VPN")
		w.Header().Set("Subscription-Userinfo", "upload=0; download=1073741824; total=10737418240; expire=4102444800")
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(panelBody))))
	}))
	defer panel.Close()
	sock := startDaemon(t)
	subURL := panel.URL + "/sub/SECRETTOKEN"

	mustRun := func(args ...string) string {
		t.Helper()
		code, out, errOut := run(append(args, "--socket", sock)...)
		if code != 0 {
			t.Fatalf("beryl %v: exit %d\n%s%s", args, code, out, errOut)
		}
		return out
	}

	out := mustRun("sub", "add", subURL)
	if !strings.Contains(out, `"Test VPN"`) || !strings.Contains(out, "2 servers") {
		t.Fatalf("sub add: %s", out)
	}

	out = mustRun("sub", "ls")
	if !strings.Contains(out, "Test VPN") || !strings.Contains(out, "1.0 GiB / 10.0 GiB") {
		t.Fatalf("sub ls: %s", out)
	}
	if strings.Contains(out, "SECRETTOKEN") {
		t.Fatal("sub ls leaks the subscription URL")
	}
	var subs []struct {
		ID        string `json:"id"`
		URLMasked string `json:"url_masked"`
	}
	if err := json.Unmarshal([]byte(mustRun("sub", "ls", "--json")), &subs); err != nil || len(subs) != 1 {
		t.Fatalf("sub ls --json: %v", err)
	}
	if strings.Contains(subs[0].URLMasked, "SECRETTOKEN") {
		t.Fatal("url_masked contains the token")
	}

	out = mustRun("servers")
	if !strings.Contains(out, "Amsterdam") || !strings.Contains(out, "reality") || !strings.Contains(out, "NL") ||
		!strings.Contains(out, "hysteria2") {
		t.Fatalf("servers: %s", out)
	}

	// Share by a unique part of the name; the link round-trips through the parser.
	out = mustRun("share", "helsin")
	if !strings.HasPrefix(out, "hysteria2://pw@h.example.com:443") {
		t.Fatalf("share: %s", out)
	}

	// Subscription link as QR (PNG) and as text.
	png := filepath.Join(t.TempDir(), "sub.png")
	mustRun("sub", "qr", "Test VPN", "--png", png)
	if data, err := os.ReadFile(png); err != nil || len(data) < 100 || string(data[1:4]) != "PNG" {
		t.Fatalf("png: %v", err)
	}
	if out = mustRun("sub", "qr", subs[0].ID[:4], "--link"); strings.TrimSpace(out) != subURL {
		t.Fatalf("sub qr --link = %q", out)
	}
	if code, _, errOut := run("share", "e", "--socket", sock); code != 1 || !strings.Contains(errOut, "matches several servers") {
		t.Fatalf("ambiguous share: exit %d %s", code, errOut)
	}
	if out = mustRun("sub", "qr", "Test VPN"); !strings.Contains(out, "▀") {
		t.Fatalf("terminal QR missing:\n%s", out)
	}

	out = mustRun("sub", "set", "Test VPN", "--name", "Main", "--interval", "6h")
	if !strings.Contains(out, "every 6h") {
		t.Fatalf("sub set: %s", out)
	}
	out = mustRun("sub", "update", "Main")
	if !strings.Contains(out, "Main: 2 servers") {
		t.Fatalf("sub update: %s", out)
	}

	out = mustRun("import", "trojan://p@t.example.com:443#Solo")
	if !strings.Contains(out, `"Solo"`) {
		t.Fatalf("import: %s", out)
	}
	out = mustRun("sub", "update", "--all")
	if strings.Contains(out, "Solo") {
		t.Fatalf("update --all touched a local subscription: %s", out)
	}

	mustRun("sub", "rm", "Main")
	mustRun("sub", "rm", "Solo")
	if out = mustRun("sub", "ls"); !strings.Contains(out, "no subscriptions") {
		t.Fatalf("after rm: %s", out)
	}
}

func TestSubAddErrors(t *testing.T) {
	sock := startDaemon(t)
	code, _, errOut := run("sub", "add", "not-a-url", "--socket", sock)
	if code != 1 || !strings.Contains(errOut, "not a subscription URL") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	code, _, errOut = run("sub", "add", "http://127.0.0.1:1/sub/SECRETTOKEN", "--socket", sock, "--timeout", "20s")
	if code != 1 || !strings.Contains(errOut, "download failed") || strings.Contains(errOut, "SECRETTOKEN") {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if strings.Contains(errOut, "not responding") || strings.Contains(errOut, "not running") {
		t.Fatalf("download failure reported as daemon failure: %s", errOut)
	}
	code, _, errOut = run("sub", "rm", "nope", "--socket", sock)
	if code != 1 || !strings.Contains(errOut, `no subscription matches "nope"`) {
		t.Fatalf("exit %d: %s", code, errOut)
	}
}
