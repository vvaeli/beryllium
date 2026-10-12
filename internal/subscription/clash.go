package subscription

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/vvaeli/beryllium/internal/model"
	"go.yaml.in/yaml/v3"
)

func isClashYAML(body []byte) bool {
	return bytes.HasPrefix(body, []byte("proxies:")) || bytes.Contains(body, []byte("\nproxies:"))
}

type clashConfig struct {
	Proxies []map[string]any `yaml:"proxies"`
}

func parseClash(body []byte) (Parsed, error) {
	var cfg clashConfig
	if err := yaml.Unmarshal(body, &cfg); err != nil {
		return Parsed{}, fmt.Errorf("invalid Clash YAML: %w", err)
	}
	var p Parsed
	for i, m := range cfg.Proxies {
		srv, err := clashToServer(cmap(m))
		if err != nil {
			p.Warnings = append(p.Warnings, fmt.Sprintf("proxy %d: %v", i+1, err))
			continue
		}
		p.Servers = append(p.Servers, srv)
	}
	return p, nil
}

// cmap reads loosely typed YAML values.
type cmap map[string]any

func (m cmap) str(k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func (m cmap) int(k string) int {
	n, _ := strconv.Atoi(m.str(k))
	return n
}

func (m cmap) bool(k string) bool { return m.str(k) == "true" }

func (m cmap) sub(k string) cmap {
	if v, ok := m[k].(map[string]any); ok {
		return v
	}
	return cmap{}
}

func (m cmap) list(k string) []string {
	var out []string
	switch v := m[k].(type) {
	case []any:
		for _, x := range v {
			out = append(out, fmt.Sprint(x))
		}
	case string:
		for _, x := range strings.Split(v, ",") {
			if x = strings.TrimSpace(x); x != "" {
				out = append(out, x)
			}
		}
	}
	return out
}

func clashToServer(m cmap) (*model.Server, error) {
	srv := &model.Server{Name: m.str("name"), Address: m.str("server"), UUID: m.str("uuid"), Password: m.str("password")}
	switch m.str("type") {
	case "vless":
		srv.Protocol, srv.Flow = model.VLESS, m.str("flow")
	case "vmess":
		srv.Protocol, srv.AlterID = model.VMess, m.int("alterId")
		if c := m.str("cipher"); c != "auto" {
			srv.Method = c
		}
	case "trojan":
		srv.Protocol = model.Trojan
	case "ss":
		srv.Protocol, srv.Method = model.Shadowsocks, m.str("cipher")
		if pl := m.str("plugin"); pl != "" {
			var opts []string
			for k, v := range m.sub("plugin-opts") {
				opts = append(opts, k+"="+fmt.Sprint(v))
			}
			srv.Plugin = &model.Plugin{Name: pl, Opts: strings.Join(opts, ";")}
		}
	case "hysteria2":
		srv.Protocol = model.Hysteria2
		h := &model.Hysteria2Opts{Obfs: m.str("obfs"), ObfsPassword: m.str("obfs-password"), Ports: m.str("ports")}
		if *h != (model.Hysteria2Opts{}) {
			srv.Hysteria2 = h
		}
		srv.TLS = &model.TLS{Security: "tls", SNI: m.str("sni"), Insecure: m.bool("skip-cert-verify"), ALPN: m.list("alpn")}
	case "tuic":
		srv.Protocol = model.TUIC
		srv.TUIC = &model.TUICOpts{CongestionControl: m.str("congestion-controller"), UDPRelayMode: m.str("udp-relay-mode")}
		srv.TLS = &model.TLS{Security: "tls", SNI: m.str("sni"), Insecure: m.bool("skip-cert-verify"), ALPN: m.list("alpn")}
	case "wireguard":
		return clashWireGuard(m, srv)
	default:
		return nil, fmt.Errorf("unsupported type %q", m.str("type"))
	}
	port := m.int("port")
	if port == 0 && srv.Protocol == model.Hysteria2 {
		port = 443
	}
	if err := setPort(srv, port); err != nil {
		return nil, err
	}
	if srv.Address == "" {
		return nil, errors.New("missing server")
	}
	if srv.Protocol == model.VLESS || srv.Protocol == model.VMess || srv.Protocol == model.Trojan {
		t := &model.Transport{Type: normalizeNetwork(m.str("network"))}
		switch t.Type {
		case "ws":
			o := m.sub("ws-opts")
			t.Path, t.Host = o.str("path"), o.sub("headers").str("Host")
		case "grpc":
			t.ServiceName = m.sub("grpc-opts").str("grpc-service-name")
		case "http":
			o := m.sub("h2-opts")
			t.Path = o.str("path")
			if hs := o.list("host"); len(hs) > 0 {
				t.Host = hs[0]
			}
		case "xhttp":
			o := m.sub("xhttp-opts")
			t.Path, t.Host, t.Mode = o.str("path"), o.str("host"), o.str("mode")
		}
		srv.Transport = t
		reality := m.sub("reality-opts")
		if m.bool("tls") || srv.Protocol == model.Trojan || len(reality) > 0 {
			sni := m.str("servername")
			if sni == "" {
				sni = m.str("sni")
			}
			tls := &model.TLS{Security: "tls", SNI: sni, Fingerprint: m.str("client-fingerprint"),
				Insecure: m.bool("skip-cert-verify"), ALPN: m.list("alpn")}
			if len(reality) > 0 {
				tls.Security, tls.PublicKey, tls.ShortID = "reality", reality.str("public-key"), reality.str("short-id")
			}
			srv.TLS = tls
		}
	}
	return srv, nil
}

func clashWireGuard(m cmap, srv *model.Server) (*model.Server, error) {
	wg := &model.WireGuardOpts{PrivateKey: m.str("private-key"), PublicKey: m.str("public-key"),
		PreSharedKey: m.str("pre-shared-key"), MTU: m.int("mtu"), AllowedIPs: m.list("allowed-ips")}
	for _, k := range []string{"ip", "ipv6"} {
		if v := m.str(k); v != "" {
			wg.Addresses = append(wg.Addresses, v)
		}
	}
	if res, ok := m["reserved"].([]any); ok {
		for _, r := range res {
			n, _ := strconv.Atoi(fmt.Sprint(r))
			wg.Reserved = append(wg.Reserved, n)
		}
	}
	srv.Protocol, srv.WireGuard = model.WireGuard, wg
	for k, v := range m.sub("amnezia-wg-option") {
		if model.IsAmneziaKey(k) {
			if wg.Amnezia == nil {
				wg.Amnezia = map[string]string{}
			}
			wg.Amnezia[strings.ToLower(k)] = fmt.Sprint(v)
			srv.Protocol = model.AmneziaWG
		}
	}
	if err := setPort(srv, m.int("port")); err != nil {
		return nil, err
	}
	if wg.PrivateKey == "" || wg.PublicKey == "" || srv.Address == "" {
		return nil, errors.New("incomplete wireguard")
	}
	return srv, nil
}
