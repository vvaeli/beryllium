package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/vvaeli/beryllium/internal/model"
)

func singBoxSupports(s *model.Server) error {
	switch s.Protocol {
	case model.VLESS, model.VMess, model.Trojan:
		if s.Encryption != "" {
			return errors.New("VLESS encryption is not supported")
		}
		if s.Flow != "" && s.Flow != "xtls-rprx-vision" {
			return fmt.Errorf("flow %q is not supported", s.Flow)
		}
		if t := s.Transport; t != nil {
			switch t.Type {
			case "tcp":
				if t.HeaderType != "" {
					return fmt.Errorf("tcp header %q is not supported", t.HeaderType)
				}
			case "ws", "http", "httpupgrade", "quic":
			case "grpc":
				if t.Mode == "multi" {
					return errors.New("gRPC multi mode is not supported")
				}
			default:
				return fmt.Errorf("transport %s is not supported", t.Type)
			}
		}
	case model.Shadowsocks:
		if s.Plugin != nil && s.Plugin.Name != "obfs-local" && s.Plugin.Name != "v2ray-plugin" {
			return fmt.Errorf("plugin %s is not supported", s.Plugin.Name)
		}
	case model.Hysteria2:
		if s.TLS != nil && s.TLS.PinSHA256 != "" {
			return errors.New("certificate pinning is not supported")
		}
	case model.TUIC, model.WireGuard:
	case model.AmneziaWG:
		return errors.New("AmneziaWG is not supported")
	default:
		return fmt.Errorf("protocol %s is not supported", s.Protocol)
	}
	return nil
}

// singBoxFront describes the sing-box front of a chain.
type singBoxFront struct {
	MixedPort int
	APIPort   int
	APISecret string
	LogLevel  string
	// Server is connected to directly; nil means forward to BackendPort.
	Server      *model.Server
	BackendPort int
}

func singBoxConfig(f singBoxFront) ([]byte, error) {
	var proxy map[string]any
	if f.Server != nil {
		var err error
		if proxy, err = singBoxOutbound(f.Server); err != nil {
			return nil, err
		}
	} else {
		proxy = map[string]any{"type": "socks", "server": "127.0.0.1", "server_port": f.BackendPort, "version": "5"}
	}
	proxy["tag"] = "proxy"
	cfg := map[string]any{
		"log": map[string]any{"level": f.LogLevel, "timestamp": false},
		"dns": map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "local"}}},
		"inbounds": []any{map[string]any{
			"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": f.MixedPort,
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "proxy", "default_domain_resolver": "local"},
		"experimental": map[string]any{"clash_api": map[string]any{
			"external_controller": fmt.Sprintf("127.0.0.1:%d", f.APIPort), "secret": f.APISecret,
		}},
	}
	if proxy["type"] == "wireguard" {
		cfg["endpoints"] = []any{proxy}
	} else {
		cfg["outbounds"] = append([]any{proxy}, cfg["outbounds"].([]any)...)
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func singBoxOutbound(s *model.Server) (map[string]any, error) {
	if err := singBoxSupports(s); err != nil {
		return nil, err
	}
	o := map[string]any{"server": s.Address, "server_port": int(s.Port)}
	switch s.Protocol {
	case model.VLESS:
		o["type"], o["uuid"], o["packet_encoding"] = "vless", s.UUID, "xudp"
		if s.Flow != "" {
			o["flow"] = s.Flow
		}
	case model.VMess:
		o["type"], o["uuid"], o["alter_id"], o["packet_encoding"] = "vmess", s.UUID, s.AlterID, "xudp"
		o["security"] = orDefault(s.Method, "auto")
	case model.Trojan:
		o["type"], o["password"] = "trojan", s.Password
	case model.Shadowsocks:
		o["type"], o["method"], o["password"] = "shadowsocks", s.Method, s.Password
		if s.Plugin != nil {
			o["plugin"], o["plugin_opts"] = s.Plugin.Name, s.Plugin.Opts
		}
	case model.Hysteria2:
		o["type"], o["password"] = "hysteria2", s.Password
		if h := s.Hysteria2; h != nil {
			if h.Ports != "" {
				o["server_ports"] = singBoxPorts(h.Ports)
			}
			if h.UpMbps > 0 {
				o["up_mbps"] = h.UpMbps
			}
			if h.DownMbps > 0 {
				o["down_mbps"] = h.DownMbps
			}
			if h.Obfs != "" {
				o["obfs"] = map[string]any{"type": h.Obfs, "password": h.ObfsPassword}
			}
		}
	case model.TUIC:
		o["type"], o["uuid"], o["password"] = "tuic", s.UUID, s.Password
		if t := s.TUIC; t != nil {
			setIf(o, "congestion_control", t.CongestionControl)
			setIf(o, "udp_relay_mode", t.UDPRelayMode)
		}
	case model.WireGuard:
		return singBoxWireGuard(s), nil
	}
	if tls := singBoxTLS(s); tls != nil {
		o["tls"] = tls
	}
	if t := singBoxTransport(s.Transport); t != nil {
		o["transport"] = t
	}
	return o, nil
}

func singBoxTLS(s *model.Server) map[string]any {
	t := s.TLS
	if t == nil {
		return nil
	}
	tls := map[string]any{"enabled": true, "server_name": orDefault(t.SNI, sniFallback(s))}
	if t.Insecure {
		tls["insecure"] = true
	}
	if len(t.ALPN) > 0 {
		tls["alpn"] = t.ALPN
	}
	if s.TUIC != nil && s.TUIC.DisableSNI {
		tls["disable_sni"] = true
	}
	fp := t.Fingerprint
	if t.Security == "reality" {
		fp = orDefault(fp, "chrome") // REALITY requires uTLS
		tls["reality"] = map[string]any{"enabled": true, "public_key": t.PublicKey, "short_id": t.ShortID}
	}
	if fp != "" && s.Protocol != model.Hysteria2 && s.Protocol != model.TUIC {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	return tls
}

func singBoxTransport(t *model.Transport) map[string]any {
	if t == nil {
		return nil
	}
	switch t.Type {
	case "ws":
		o := map[string]any{"type": "ws"}
		path, ed := splitEarlyData(t.Path)
		setIf(o, "path", path)
		if t.Host != "" {
			o["headers"] = map[string]any{"Host": t.Host}
		}
		if ed > 0 {
			o["max_early_data"], o["early_data_header_name"] = ed, "Sec-WebSocket-Protocol"
		}
		return o
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": t.ServiceName}
	case "http":
		o := map[string]any{"type": "http"}
		setIf(o, "path", t.Path)
		if t.Host != "" {
			o["host"] = splitComma(t.Host)
		}
		return o
	case "httpupgrade":
		o := map[string]any{"type": "httpupgrade"}
		setIf(o, "path", t.Path)
		setIf(o, "host", t.Host)
		return o
	case "quic":
		return map[string]any{"type": "quic"}
	}
	return nil
}

func singBoxWireGuard(s *model.Server) map[string]any {
	wg := s.WireGuard
	peer := map[string]any{
		"address": s.Address, "port": int(s.Port), "public_key": wg.PublicKey,
		"allowed_ips": orDefaultList(wg.AllowedIPs, []string{"0.0.0.0/0", "::/0"}),
	}
	setIf(peer, "pre_shared_key", wg.PreSharedKey)
	if wg.Keepalive > 0 {
		peer["persistent_keepalive_interval"] = wg.Keepalive
	}
	if len(wg.Reserved) > 0 {
		peer["reserved"] = wg.Reserved
	}
	o := map[string]any{
		"type": "wireguard", "address": withPrefix(wg.Addresses), "private_key": wg.PrivateKey,
		"peers": []any{peer},
	}
	if wg.MTU > 0 {
		o["mtu"] = wg.MTU
	}
	return o
}

// singBoxPorts converts "443,20000-30000" into ["443:443","20000:30000"].
func singBoxPorts(spec string) []string {
	var out []string
	for _, p := range splitComma(spec) {
		p = strings.ReplaceAll(p, "-", ":")
		if !strings.Contains(p, ":") {
			p += ":" + p
		}
		out = append(out, p)
	}
	return out
}

// splitEarlyData extracts Xray-style "?ed=2048" from a WebSocket path.
func splitEarlyData(path string) (string, int) {
	p, q, ok := strings.Cut(path, "?")
	if !ok {
		return path, 0
	}
	vals, err := url.ParseQuery(q)
	if err != nil {
		return path, 0
	}
	ed, err := strconv.Atoi(vals.Get("ed"))
	if err != nil {
		return path, 0
	}
	vals.Del("ed")
	if rest := vals.Encode(); rest != "" {
		p += "?" + rest
	}
	return p, ed
}

// withPrefix adds /32 or /128 to bare interface addresses.
func withPrefix(addrs []string) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		switch {
		case strings.Contains(a, "/"):
		case strings.Contains(a, ":"):
			a += "/128"
		default:
			a += "/32"
		}
		out = append(out, a)
	}
	return out
}

func sniFallback(s *model.Server) string {
	if s.Transport != nil && s.Transport.Host != "" {
		return s.Transport.Host
	}
	return s.Address
}

func setIf(m map[string]any, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func orDefaultList(v, def []string) []string {
	if len(v) == 0 {
		return def
	}
	return v
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
