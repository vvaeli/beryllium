package link

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/vvaeli/beryllium/internal/model"
)

// All credentials below are fake.
const (
	uuid   = "0b6e9f2c-1a2b-4c3d-8e9f-0123456789ab"
	wgPriv = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	wgPub  = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
)

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want *model.Server
	}{
		{
			name: "vless reality vision",
			in:   "vless://" + uuid + "@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=PUBKEY_abc-123&sid=6ba85179e30d4fc2&spx=%2F&type=tcp&headerType=none#%F0%9F%87%B3%F0%9F%87%B1%20NL%20Reality",
			want: &model.Server{
				Name: "🇳🇱 NL Reality", Country: "NL", Protocol: model.VLESS, Address: "1.2.3.4", Port: 443,
				UUID: uuid, Flow: "xtls-rprx-vision",
				Transport: &model.Transport{Type: "tcp"},
				TLS: &model.TLS{Security: "reality", SNI: "www.example.com", Fingerprint: "chrome",
					PublicKey: "PUBKEY_abc-123", ShortID: "6ba85179e30d4fc2", SpiderX: "/"},
			},
		},
		{
			name: "vless xhttp tls ipv6",
			in:   "vless://" + uuid + "@[2001:db8::1]:8443?security=tls&type=xhttp&path=%2Fxh&host=cdn.example.com&mode=auto&alpn=h2,http/1.1&extra=%7B%22a%22%3A1%7D#x",
			want: &model.Server{
				Name: "x", Protocol: model.VLESS, Address: "2001:db8::1", Port: 8443, UUID: uuid,
				Transport: &model.Transport{Type: "xhttp", Path: "/xh", Host: "cdn.example.com", Mode: "auto", Extra: `{"a":1}`},
				TLS:       &model.TLS{Security: "tls", ALPN: []string{"h2", "http/1.1"}},
			},
		},
		{
			name: "vless grpc splithttp alias",
			in:   "vless://" + uuid + "@h.example.com:443?type=splithttp&security=none",
			want: &model.Server{Protocol: model.VLESS, Address: "h.example.com", Port: 443, UUID: uuid,
				Transport: &model.Transport{Type: "xhttp"}},
		},
		{
			name: "trojan ws defaults to tls",
			in:   "trojan://p%40ss@t.example.com:443?type=ws&path=%2Fws&host=t.example.com&sni=t.example.com&allowInsecure=1#Trojan",
			want: &model.Server{Name: "Trojan", Protocol: model.Trojan, Address: "t.example.com", Port: 443, Password: "p@ss",
				Transport: &model.Transport{Type: "ws", Path: "/ws", Host: "t.example.com"},
				TLS:       &model.TLS{Security: "tls", SNI: "t.example.com", Insecure: true}},
		},
		{
			name: "vmess base64 json with numeric port",
			in: "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"VM","add":"v.example.com","port":443,"id":"`+uuid+
				`","aid":"0","scy":"auto","net":"grpc","type":"none","host":"","path":"svc","tls":"tls","sni":"v.example.com"}`)),
			want: &model.Server{Name: "VM", Protocol: model.VMess, Address: "v.example.com", Port: 443, UUID: uuid,
				Transport: &model.Transport{Type: "grpc", ServiceName: "svc"},
				TLS:       &model.TLS{Security: "tls", SNI: "v.example.com"}},
		},
		{
			name: "ss sip002 base64 userinfo",
			in:   "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:secret")) + "@s.example.com:8388#SS",
			want: &model.Server{Name: "SS", Protocol: model.Shadowsocks, Address: "s.example.com", Port: 8388,
				Method: "aes-256-gcm", Password: "secret"},
		},
		{
			name: "ss 2022 plain userinfo with plugin",
			in:   "ss://2022-blake3-aes-128-gcm:a2V5a2V5a2V5a2V5a2V5aw%3D%3D@s.example.com:443/?plugin=obfs-local%3Bobfs%3Dhttp#S",
			want: &model.Server{Name: "S", Protocol: model.Shadowsocks, Address: "s.example.com", Port: 443,
				Method: "2022-blake3-aes-128-gcm", Password: "a2V5a2V5a2V5a2V5a2V5aw==",
				Plugin: &model.Plugin{Name: "obfs-local", Opts: "obfs=http"}},
		},
		{
			name: "ss legacy",
			in:   "ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw@9.9.9.9:1234")) + "#Old",
			want: &model.Server{Name: "Old", Protocol: model.Shadowsocks, Address: "9.9.9.9", Port: 1234,
				Method: "chacha20-ietf-poly1305", Password: "pw"},
		},
		{
			name: "hysteria2 with port hopping and obfs",
			in:   "hy2://pass@h.example.com:443,20000-30000/?sni=h.example.com&obfs=salamander&obfs-password=ob&insecure=1#HY",
			want: &model.Server{Name: "HY", Protocol: model.Hysteria2, Address: "h.example.com", Port: 443, Password: "pass",
				Hysteria2: &model.Hysteria2Opts{Obfs: "salamander", ObfsPassword: "ob", Ports: "443,20000-30000"},
				TLS:       &model.TLS{Security: "tls", SNI: "h.example.com", Insecure: true}},
		},
		{
			name: "tuic",
			in:   "tuic://" + uuid + ":pw@t.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=t.example.com#T",
			want: &model.Server{Name: "T", Protocol: model.TUIC, Address: "t.example.com", Port: 443, UUID: uuid, Password: "pw",
				TUIC: &model.TUICOpts{CongestionControl: "bbr", UDPRelayMode: "native"},
				TLS:  &model.TLS{Security: "tls", SNI: "t.example.com", ALPN: []string{"h3"}}},
		},
		{
			name: "wireguard keeps plus signs in keys",
			in:   "wireguard://" + wgPriv + "@w.example.com:51820?publickey=" + wgPub + "&address=10.0.0.2/32,fd00::2/128&mtu=1280&reserved=1,2,3#WG",
			want: &model.Server{Name: "WG", Protocol: model.WireGuard, Address: "w.example.com", Port: 51820,
				WireGuard: &model.WireGuardOpts{PrivateKey: wgPriv, PublicKey: wgPub,
					Addresses: []string{"10.0.0.2/32", "fd00::2/128"}, MTU: 1280, Reserved: []int{1, 2, 3}}},
		},
		{
			name: "awg link",
			in:   "awg://" + escape(wgPriv) + "@a.example.com:51820?publickey=" + escape(wgPub) + "&address=10.8.1.2/32&jc=4&jmin=40&jmax=70&s1=0&s2=0&h1=1-100&h2=200#AWG",
			want: &model.Server{Name: "AWG", Protocol: model.AmneziaWG, Address: "a.example.com", Port: 51820,
				WireGuard: &model.WireGuardOpts{PrivateKey: wgPriv, PublicKey: wgPub, Addresses: []string{"10.8.1.2/32"},
					Amnezia: map[string]string{"jc": "4", "jmin": "40", "jmax": "70", "s1": "0", "s2": "0", "h1": "1-100", "h2": "200"}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				g, _ := json.MarshalIndent(got, "", " ")
				w, _ := json.MarshalIndent(tt.want, "", " ")
				t.Fatalf("got  %s\nwant %s", g, w)
			}
			// Round trip: Parse(Encode(x)) == x.
			enc, err := Encode(got)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			again, err := Parse(enc)
			if err != nil {
				t.Fatalf("Parse(Encode): %v\nlink: %s", err, enc)
			}
			if !reflect.DeepEqual(again, got) {
				g, _ := json.MarshalIndent(again, "", " ")
				w, _ := json.MarshalIndent(got, "", " ")
				t.Fatalf("round trip mismatch\nlink: %s\ngot  %s\nwant %s", enc, g, w)
			}
		})
	}
}

func TestParseErrorsDoNotLeakLink(t *testing.T) {
	secret := "SECRETSECRET"
	for _, in := range []string{
		"vless://" + secret + "@host",           // no port
		"trojan://" + secret + "@:443",          // no host
		"vmess://" + secret,                     // not base64 json
		"ss://" + secret,                        // bad payload
		"tuic://" + secret + "@h.example.com:1", // no password
		"socks://" + secret,                     // unsupported
		"vpn://" + secret,
	} {
		_, err := Parse(in)
		if err == nil {
			t.Errorf("Parse(%q) succeeded", in)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaks link contents: %v", err)
		}
	}
	if _, err := Parse("socks://x"); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unknown scheme err = %v, want ErrUnsupported", err)
	}
}

func TestIsRouting(t *testing.T) {
	for in, want := range map[string]bool{
		"happ://routing/onadd/eyJ9":   true,
		"incy://routing/add/eyJ9":     true,
		"://routing/onadd/eyJ9":       true,
		"HAPP://ROUTING/ADD/x":        true,
		"vless://routing/x@h:1":       false,
		"https://example.com/routing": false,
	} {
		if got := IsRouting(in); got != want {
			t.Errorf("IsRouting(%q) = %v, want %v", in, got, want)
		}
	}
}

const awgConf = `[Interface]
PrivateKey = ` + wgPriv + `
Address = 10.8.1.2/32
DNS = 1.1.1.1, 1.0.0.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = ` + wgPub + `
PresharedKey = psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.5:51820
PersistentKeepalive = 25
`

func TestParseWireGuardConf(t *testing.T) {
	srv, err := ParseWireGuardConf(awgConf, "🇩🇪 Home")
	if err != nil {
		t.Fatal(err)
	}
	want := &model.Server{Name: "🇩🇪 Home", Country: "DE", Protocol: model.AmneziaWG, Address: "203.0.113.5", Port: 51820,
		WireGuard: &model.WireGuardOpts{PrivateKey: wgPriv, PublicKey: wgPub, PreSharedKey: "psk",
			Addresses: []string{"10.8.1.2/32"}, AllowedIPs: []string{"0.0.0.0/0", "::/0"}, DNS: []string{"1.1.1.1", "1.0.0.1"},
			Keepalive: 25, Amnezia: map[string]string{"jc": "4", "jmin": "40", "jmax": "70", "s1": "0", "s2": "0",
				"h1": "1", "h2": "2", "h3": "3", "h4": "4"}}}
	if !reflect.DeepEqual(srv, want) {
		g, _ := json.MarshalIndent(srv, "", " ")
		t.Fatalf("got %s", g)
	}
	plain := strings.NewReplacer("Jc = 4\n", "", "Jmin = 40\n", "", "Jmax = 70\n", "", "S1 = 0\n", "", "S2 = 0\n", "",
		"H1 = 1\n", "", "H2 = 2\n", "", "H3 = 3\n", "", "H4 = 4\n", "").Replace(awgConf)
	if srv, err := ParseWireGuardConf(plain, "x"); err != nil || srv.Protocol != model.WireGuard {
		t.Fatalf("plain WireGuard conf: %v, %v", srv, err)
	}
}

// amneziaLink builds a vpn:// string the way the Amnezia client does.
func amneziaLink(t *testing.T, conf string) string {
	t.Helper()
	lastConfig, _ := json.Marshal(map[string]string{"config": conf})
	doc, _ := json.Marshal(map[string]any{
		"description": "My AWG",
		"containers": []any{map[string]any{
			"container": "amnezia-awg",
			"awg":       map[string]string{"last_config": string(lastConfig)},
		}},
	})
	var z bytes.Buffer
	binary.Write(&z, binary.BigEndian, uint32(len(doc)))
	zw := zlib.NewWriter(&z)
	zw.Write(doc)
	zw.Close()
	return "vpn://" + base64.RawURLEncoding.EncodeToString(z.Bytes())
}

func TestParseAmneziaVPN(t *testing.T) {
	srv, err := Parse(amneziaLink(t, awgConf))
	if err != nil {
		t.Fatal(err)
	}
	if srv.Protocol != model.AmneziaWG || srv.Name != "My AWG" || srv.WireGuard.Amnezia["jc"] != "4" || srv.Port != 51820 {
		g, _ := json.Marshal(srv)
		t.Fatalf("unexpected server %s", g)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"vless://" + uuid + "@1.2.3.4:443?security=reality&pbk=x#n",
		"hy2://p@h:443,1000-2000/?obfs=salamander",
		"ss://YWVzLTI1Ni1nY206cA@h:1#x",
		"vmess://e30=",
		"wireguard://k@h:1?publickey=p",
		"vpn://AAAA",
		"tuic://a:b@[::1]:1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		srv, err := Parse(s)
		if err != nil {
			return
		}
		// Anything that parses must encode and parse back.
		enc, err := Encode(srv)
		if err != nil {
			t.Fatalf("Encode after successful Parse: %v", err)
		}
		if _, err := Parse(enc); err != nil {
			t.Fatalf("Parse(Encode(Parse(%q))) = %v (link %q)", s, err, enc)
		}
	})
}
