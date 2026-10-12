package core

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/vvaeli/beryllium/internal/link"
	"github.com/vvaeli/beryllium/internal/model"
)

// testBinaries returns the cores fetched by `go -C tools run ./fetchcores`,
// skipping the test when they are absent.
func testBinaries(t *testing.T) *Binaries {
	t.Helper()
	dir, _ := filepath.Abs(filepath.Join("..", "..", "cores", "bin", runtime.GOOS+"-"+runtime.GOARCH))
	b := LoadBinaries(dir)
	for _, k := range Kinds {
		if !b.Installed(k) {
			t.Skipf("%s not found in %s; run: go -C tools run ./fetchcores", k, dir)
		}
	}
	return b
}

const (
	tUUID   = "0b6e9f2c-1a2b-4c3d-8e9f-0123456789ab"
	tWGPriv = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	tWGPub  = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	tPBK    = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"
)

// corpus covers every protocol/transport combination the parsers produce.
var corpus = map[string]string{
	"vless-reality-vision": "vless://" + tUUID + "@1.2.3.4:443?security=reality&sni=www.example.com&fp=chrome&pbk=" + tPBK + "&sid=6ba85179e30d4fc2&type=tcp&flow=xtls-rprx-vision",
	"vless-xhttp-reality":  "vless://" + tUUID + "@1.2.3.4:443?security=reality&sni=www.example.com&pbk=" + tPBK + "&sid=ab&type=xhttp&path=%2Fx&mode=auto&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D",
	"vless-ws-tls-ed":      "vless://" + tUUID + "@cdn.example.com:443?security=tls&sni=cdn.example.com&type=ws&path=%2Fws%3Fed%3D2048&host=cdn.example.com&alpn=h2,http/1.1&fp=firefox",
	"vless-grpc-tls":       "vless://" + tUUID + "@g.example.com:443?security=tls&type=grpc&serviceName=svc",
	"vless-httpupgrade":    "vless://" + tUUID + "@h.example.com:80?security=none&type=httpupgrade&path=%2Fu&host=h.example.com",
	"vless-tcp-http-hdr":   "vless://" + tUUID + "@t.example.com:80?security=none&type=tcp&headerType=http",
	"vless-h2":             "vless://" + tUUID + "@h2.example.com:443?security=tls&type=http&path=%2Fh2&host=h2.example.com",
	"vmess-ws":             "vmess://eyJ2IjoiMiIsInBzIjoidm0iLCJhZGQiOiJ2LmV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMGI2ZTlmMmMtMWEyYi00YzNkLThlOWYtMDEyMzQ1Njc4OWFiIiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyIsInR5cGUiOiJub25lIiwiaG9zdCI6InYuZXhhbXBsZS5jb20iLCJwYXRoIjoiL3ZtIiwidGxzIjoidGxzIiwic25pIjoidi5leGFtcGxlLmNvbSJ9",
	"trojan-tls":           "trojan://pass@t.example.com:443?sni=t.example.com&allowInsecure=1",
	"ss-aead":              "ss://YWVzLTI1Ni1nY206c2VjcmV0@s.example.com:8388",
	"ss-2022":              "ss://2022-blake3-aes-128-gcm:YWFhYWFhYWFhYWFhYWFhYQ%3D%3D@s.example.com:443",
	"ss-obfs":              "ss://YWVzLTI1Ni1nY206c2VjcmV0@s.example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com",
	"hy2-hop-obfs":         "hy2://pw@h.example.com:443,20000-30000/?sni=h.example.com&obfs=salamander&obfs-password=ob&insecure=1",
	"hy2-pinned":           "hy2://pw@h.example.com:443/?sni=h.example.com&pinSHA256=" + strings.Repeat("ab", 32),
	"tuic":                 "tuic://" + tUUID + ":pw@t.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=t.example.com",
	"wireguard":            "wireguard://" + tWGPriv + "@w.example.com:51820?publickey=" + tWGPub + "&address=10.0.0.2/32,fd00::2/128&mtu=1280&reserved=1,2,3",
	"amneziawg":            "awg://" + tWGPriv + "@a.example.com:51820?publickey=" + tWGPub + "&address=10.8.1.2/32&jc=4&jmin=40&jmax=70&s1=0&s2=0&h1=1&h2=2&h3=3&h4=4",
}

func corpusServer(t *testing.T, name string) *model.Server {
	t.Helper()
	srv, err := link.Parse(corpus[name])
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return srv
}

func TestChooseMatrix(t *testing.T) {
	want := map[string]Kind{
		"vless-reality-vision": SingBox,
		"vless-xhttp-reality":  Xray,
		"vless-tcp-http-hdr":   Xray,
		"vless-h2":             SingBox,
		"ss-obfs":              SingBox,
		"hy2-hop-obfs":         SingBox,
		"hy2-pinned":           Mihomo,
		"tuic":                 SingBox,
		"wireguard":            SingBox,
		"amneziawg":            Mihomo,
		"trojan-tls":           SingBox,
	}
	for name, k := range want {
		c, err := Choose(corpusServer(t, name), "", nil)
		if err != nil || c.Kind != k {
			t.Errorf("%s: Choose = %+v, %v; want %s", name, c, err, k)
		}
	}
	c, _ := Choose(corpusServer(t, "amneziawg"), "", nil)
	if !strings.Contains(c.Reason, "only capable") {
		t.Errorf("AWG reason = %q", c.Reason)
	}
	if _, err := Choose(corpusServer(t, "amneziawg"), SingBox, nil); !errors.Is(err, ErrNoCore) {
		t.Errorf("override to an incapable core: %v", err)
	}
	if _, err := Choose(corpusServer(t, "vless-xhttp-reality"), "", func(k Kind) bool { return k != Xray }); !errors.Is(err, ErrNoCore) {
		t.Errorf("xhttp without xray installed: %v", err)
	}
}

func TestWebSocketALPN(t *testing.T) {
	out, err := singBoxOutbound(corpusServer(t, "vless-ws-tls-ed"))
	if err != nil {
		t.Fatal(err)
	}
	if alpn := out["tls"].(map[string]any)["alpn"]; !reflect.DeepEqual(alpn, []string{"http/1.1"}) {
		t.Fatalf("ws alpn = %v, want [http/1.1]", alpn)
	}
	out, _ = singBoxOutbound(corpusServer(t, "vless-h2"))
	if _, ok := out["tls"].(map[string]any)["alpn"]; ok {
		t.Fatal("alpn added where the link had none")
	}
}

// TestConfigsPassCoreCheck validates every generated config with the core's
// own checker, for every core that claims support.
func TestConfigsPassCoreCheck(t *testing.T) {
	bins := testBinaries(t)
	for name := range corpus {
		srv := corpusServer(t, name)
		for _, k := range Kinds {
			if supports(k, srv) != nil {
				continue
			}
			t.Run(name+"/"+string(k), func(t *testing.T) {
				dir := t.TempDir()
				var (
					cfg  []byte
					err  error
					args []string
					file string
				)
				switch k {
				case SingBox:
					file = filepath.Join(dir, "config.json")
					cfg, err = singBoxConfig(singBoxFront{MixedPort: 2080, APIPort: 2081, APISecret: "s", LogLevel: "warn", Server: srv})
					args = []string{"check", "-c", file}
				case Xray:
					file = filepath.Join(dir, "config.json")
					cfg, err = xrayConfig(srv, 2080, "warning")
					args = []string{"run", "-test", "-c", file}
				case Mihomo:
					file = filepath.Join(dir, "config.yaml")
					cfg, err = mihomoConfig(srv, 2080, "warning")
					args = []string{"-t", "-d", dir, "-f", file}
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, cfg, 0o600); err != nil {
					t.Fatal(err)
				}
				out, err := exec.Command(bins.Path(k), args...).CombinedOutput()
				if err != nil {
					t.Fatalf("%s rejected the config: %v\n%s\nconfig:\n%s", k, err, out, cfg)
				}
			})
		}
	}
	// The forwarding front used for Xray/mihomo chains.
	t.Run("front-socks", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "config.json")
		cfg, _ := singBoxConfig(singBoxFront{MixedPort: 2080, APIPort: 2081, APISecret: "s", LogLevel: "warn", BackendPort: 2082})
		os.WriteFile(file, cfg, 0o600)
		if out, err := exec.Command(bins.Path(SingBox), "check", "-c", file).CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
	})
}
