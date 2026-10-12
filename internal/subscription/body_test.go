package subscription

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/vvaeli/beryllium/internal/model"
)

const uuid = "0b6e9f2c-1a2b-4c3d-8e9f-0123456789ab"

var linkList = strings.Join([]string{
	"vless://" + uuid + "@1.2.3.4:443?security=reality&sni=a.com&pbk=K&sid=1&type=tcp&flow=xtls-rprx-vision#%F0%9F%87%B3%F0%9F%87%B1%20NL",
	"hy2://pw@h.example.com:443?sni=h.example.com#%F0%9F%87%A9%F0%9F%87%AA%20DE",
	"happ://routing/onadd/eyJOYW1lIjoiWCJ9",
	"socks://unsupported",
	"vless://broken",
	"",
	"# comment",
}, "\n")

func TestParseBodyFormats(t *testing.T) {
	for name, body := range map[string]string{
		"plain":            linkList,
		"base64 std":       base64.StdEncoding.EncodeToString([]byte(linkList)),
		"base64 url nopad": base64.RawURLEncoding.EncodeToString([]byte(linkList)),
		"base64 wrapped":   wrap(base64.StdEncoding.EncodeToString([]byte(linkList)), 76),
		"bom crlf":         "\xef\xbb\xbf" + strings.ReplaceAll(linkList, "\n", "\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			p, err := ParseBody([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Servers) != 2 || len(p.Routing) != 1 || len(p.Warnings) != 2 {
				t.Fatalf("servers=%d routing=%d warnings=%v", len(p.Servers), len(p.Routing), p.Warnings)
			}
			if p.Servers[0].Country != "NL" || p.Servers[1].Country != "DE" {
				t.Errorf("countries = %s, %s", p.Servers[0].Country, p.Servers[1].Country)
			}
		})
	}
}

func wrap(s string, n int) string {
	var b strings.Builder
	for len(s) > n {
		b.WriteString(s[:n] + "\n")
		s = s[n:]
	}
	return b.String() + s
}

func TestParseBodyEmpty(t *testing.T) {
	for _, body := range []string{"", "   ", "socks://a\nhttp://b"} {
		if _, err := ParseBody([]byte(body)); err == nil {
			t.Errorf("ParseBody(%q) succeeded", body)
		}
	}
}

func TestParseClash(t *testing.T) {
	body := `
mixed-port: 7890
proxies:
  - name: "🇫🇮 Reality"
    type: vless
    server: f.example.com
    port: 443
    uuid: ` + uuid + `
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    servername: www.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: PUB
      short-id: abcd
  - name: ws
    type: trojan
    server: t.example.com
    port: 443
    password: pw
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example.com
  - name: awg
    type: wireguard
    server: w.example.com
    port: 51820
    ip: 10.0.0.2
    private-key: PRIV
    public-key: PUB
    amnezia-wg-option:
      jc: 4
      jmin: 40
  - name: hy
    type: hysteria2
    server: h.example.com
    port: 443
    password: x
  - name: http
    type: http
    server: x
    port: 1
`
	p, err := ParseBody([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Servers) != 4 || len(p.Warnings) != 1 {
		t.Fatalf("servers=%d warnings=%v", len(p.Servers), p.Warnings)
	}
	v := p.Servers[0]
	if v.Protocol != model.VLESS || v.TLS.Security != "reality" || v.TLS.PublicKey != "PUB" || v.Flow != "xtls-rprx-vision" || v.Country != "FI" {
		t.Errorf("vless = %+v tls=%+v", v, v.TLS)
	}
	if tr := p.Servers[1]; tr.Transport.Type != "ws" || tr.Transport.Host != "cdn.example.com" || tr.TLS == nil {
		t.Errorf("trojan = %+v", tr)
	}
	if a := p.Servers[2]; a.Protocol != model.AmneziaWG || a.WireGuard.Amnezia["jc"] != "4" {
		t.Errorf("awg = %+v", a)
	}
}

func TestParseSingBox(t *testing.T) {
	body := `{"outbounds":[
	  {"type":"selector","tag":"select","outbounds":["a"]},
	  {"type":"vless","tag":"a","server":"v.example.com","server_port":443,"uuid":"` + uuid + `","flow":"xtls-rprx-vision",
	   "tls":{"enabled":true,"server_name":"s.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"P","short_id":"1"}}},
	  {"type":"hysteria2","tag":"h","server":"h.example.com","server_ports":["20000:30000"],"password":"p","obfs":{"type":"salamander","password":"o"},"tls":{"enabled":true}},
	  {"type":"direct","tag":"direct"}],
	 "endpoints":[{"type":"wireguard","tag":"wg","address":["10.0.0.2/32"],"private_key":"K","peers":[{"address":"w.example.com","port":51820,"public_key":"PK","allowed_ips":["0.0.0.0/0"]}]}]}`
	p, err := ParseBody([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Servers) != 3 || len(p.Warnings) != 0 {
		t.Fatalf("servers=%d warnings=%v", len(p.Servers), p.Warnings)
	}
	if v := p.Servers[0]; v.TLS.Security != "reality" || v.TLS.Fingerprint != "chrome" || v.Transport.Type != "tcp" {
		t.Errorf("vless = %+v", v)
	}
	if h := p.Servers[1]; h.Port != 443 || h.Hysteria2.Ports != "20000:30000" || h.Hysteria2.Obfs != "salamander" {
		t.Errorf("hy2 = %+v %+v", h, h.Hysteria2)
	}
	if w := p.Servers[2]; w.Protocol != model.WireGuard || w.Address != "w.example.com" || w.WireGuard.PublicKey != "PK" {
		t.Errorf("wg = %+v", w)
	}
}

func TestParseXrayJSONArray(t *testing.T) {
	body := `[{"remarks":"🇳🇱 NL","outbounds":[
	  {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"n.example.com","port":443,"users":[{"id":"` + uuid + `","encryption":"none","flow":""}]}]},
	   "streamSettings":{"network":"xhttp","security":"reality","realitySettings":{"serverName":"s.com","fingerprint":"chrome","publicKey":"P","shortId":"ab"},
	   "xhttpSettings":{"path":"/x","mode":"auto","extra":{"xPaddingBytes":"100-1000"}}}},
	  {"tag":"direct","protocol":"freedom"}]},
	 {"remarks":"Trojan","outbounds":[{"tag":"proxy","protocol":"trojan","settings":{"servers":[{"address":"t.example.com","port":443,"password":"pw"}]},
	   "streamSettings":{"network":"ws","security":"tls","wsSettings":{"path":"/ws","headers":{"Host":"h.com"}},"tlsSettings":{"serverName":"h.com"}}}]}]`
	p, err := ParseBody([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Servers) != 2 {
		t.Fatalf("servers=%d warnings=%v", len(p.Servers), p.Warnings)
	}
	v := p.Servers[0]
	if v.Name != "🇳🇱 NL" || v.Country != "NL" || v.Transport.Type != "xhttp" || v.Transport.Extra != `{"xPaddingBytes":"100-1000"}` || v.TLS.PublicKey != "P" {
		t.Errorf("vless = %+v %+v %+v", v, v.Transport, v.TLS)
	}
	if tr := p.Servers[1]; tr.Transport.Host != "h.com" || tr.TLS.SNI != "h.com" {
		t.Errorf("trojan = %+v", tr)
	}
}

func TestParseConfigWireGuard(t *testing.T) {
	conf := "[Interface]\nPrivateKey = K\nAddress = 10.0.0.2/32\nJc = 3\n\n[Peer]\nPublicKey = P\nEndpoint = 1.2.3.4:51820\n"
	p, err := ParseConfig([]byte(conf), "home.conf", "")
	if err != nil || len(p.Servers) != 1 || p.Servers[0].Protocol != model.AmneziaWG || p.Servers[0].Name != "home" {
		t.Fatalf("ParseConfig = %+v, %v", p, err)
	}
}
