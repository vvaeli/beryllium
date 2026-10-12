package core

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vvaeli/beryllium/internal/model"
)

func xraySupports(s *model.Server) error {
	if s.TLS != nil && s.TLS.Insecure {
		return errors.New("skipping certificate verification (allowInsecure) was removed from Xray")
	}
	switch s.Protocol {
	case model.VLESS, model.VMess, model.Trojan:
		if t := s.Transport; t != nil {
			switch t.Type {
			case "tcp", "ws", "grpc", "httpupgrade", "xhttp", "kcp":
			case "http":
				return errors.New("HTTP/2 transport was removed from Xray")
			default:
				return fmt.Errorf("transport %s is not supported", t.Type)
			}
		}
	case model.Shadowsocks:
		if s.Plugin != nil {
			return errors.New("shadowsocks plugins are not supported")
		}
	default:
		return fmt.Errorf("protocol %s is not supported here", s.Protocol)
	}
	return nil
}

// xrayConfig builds an Xray config with a loopback SOCKS inbound on
// socksPort and srv as the only outbound.
func xrayConfig(s *model.Server, socksPort int, logLevel string) ([]byte, error) {
	return xrayMultiConfig([]*model.Server{s}, []int{socksPort}, logLevel)
}

// xrayMultiConfig maps the SOCKS inbound on ports[i] to servers[i].
func xrayMultiConfig(servers []*model.Server, ports []int, logLevel string) ([]byte, error) {
	var inbounds, outbounds, rules []any
	for i, s := range servers {
		out, err := xrayOutbound(s)
		if err != nil {
			return nil, err
		}
		in, tag := fmt.Sprintf("in-%d", i), fmt.Sprintf("proxy-%d", i)
		if len(servers) == 1 {
			in, tag = "socks-in", "proxy"
		}
		out["tag"] = tag
		outbounds = append(outbounds, out)
		inbounds = append(inbounds, map[string]any{
			"tag": in, "listen": "127.0.0.1", "port": ports[i], "protocol": "socks",
			"settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"},
		})
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []string{in}, "outboundTag": tag})
	}
	cfg := map[string]any{
		"log":       map[string]any{"loglevel": logLevel},
		"inbounds":  inbounds,
		"outbounds": outbounds,
	}
	if len(servers) > 1 {
		cfg["routing"] = map[string]any{"rules": rules}
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func xrayOutbound(s *model.Server) (map[string]any, error) {
	if err := xraySupports(s); err != nil {
		return nil, err
	}
	out := map[string]any{"protocol": string(s.Protocol)}
	switch s.Protocol {
	case model.VLESS:
		user := map[string]any{"id": s.UUID, "encryption": orDefault(s.Encryption, "none")}
		setIf(user, "flow", s.Flow)
		out["settings"] = map[string]any{"vnext": []any{map[string]any{"address": s.Address, "port": int(s.Port), "users": []any{user}}}}
	case model.VMess:
		user := map[string]any{"id": s.UUID, "alterId": s.AlterID, "security": orDefault(s.Method, "auto")}
		out["settings"] = map[string]any{"vnext": []any{map[string]any{"address": s.Address, "port": int(s.Port), "users": []any{user}}}}
	case model.Trojan:
		out["settings"] = map[string]any{"servers": []any{map[string]any{"address": s.Address, "port": int(s.Port), "password": s.Password}}}
	case model.Shadowsocks:
		out["settings"] = map[string]any{"servers": []any{map[string]any{"address": s.Address, "port": int(s.Port),
			"method": s.Method, "password": s.Password}}}
	}
	if s.Protocol != model.Shadowsocks {
		stream, err := xrayStream(s)
		if err != nil {
			return nil, err
		}
		out["streamSettings"] = stream
	}
	return out, nil
}

func xrayStream(s *model.Server) (map[string]any, error) {
	t := s.Transport
	if t == nil {
		t = &model.Transport{Type: "tcp"}
	}
	st := map[string]any{"network": t.Type}
	switch t.Type {
	case "tcp":
		st["network"] = "raw"
		if t.HeaderType != "" {
			st["rawSettings"] = map[string]any{"header": map[string]any{"type": t.HeaderType}}
		}
	case "ws":
		ws := map[string]any{}
		setIf(ws, "path", t.Path)
		setIf(ws, "host", t.Host)
		st["wsSettings"] = ws
	case "grpc":
		st["grpcSettings"] = map[string]any{"serviceName": t.ServiceName, "multiMode": t.Mode == "multi"}
	case "httpupgrade":
		hu := map[string]any{}
		setIf(hu, "path", t.Path)
		setIf(hu, "host", t.Host)
		st["httpupgradeSettings"] = hu
	case "xhttp":
		xh := map[string]any{}
		setIf(xh, "path", t.Path)
		setIf(xh, "host", t.Host)
		setIf(xh, "mode", t.Mode)
		if t.Extra != "" {
			var extra any
			if err := json.Unmarshal([]byte(t.Extra), &extra); err != nil {
				return nil, errors.New("xhttp extra is not valid JSON")
			}
			xh["extra"] = extra
		}
		st["xhttpSettings"] = xh
	case "kcp":
		if t.HeaderType != "" {
			st["kcpSettings"] = map[string]any{"header": map[string]any{"type": t.HeaderType}}
		}
	}
	if tls := s.TLS; tls != nil {
		st["security"] = tls.Security
		switch tls.Security {
		case "reality":
			r := map[string]any{"serverName": tls.SNI, "fingerprint": orDefault(tls.Fingerprint, "chrome"),
				"publicKey": tls.PublicKey, "shortId": tls.ShortID}
			setIf(r, "spiderX", tls.SpiderX)
			st["realitySettings"] = r
		case "tls":
			ts := map[string]any{"serverName": orDefault(tls.SNI, sniFallback(s))}
			setIf(ts, "fingerprint", tls.Fingerprint)
			if len(tls.ALPN) > 0 {
				ts["alpn"] = tls.ALPN
			}
			st["tlsSettings"] = ts
		}
	}
	return st, nil
}
