package core

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vvaeli/beryllium/internal/model"
	"go.yaml.in/yaml/v3"
)

// mihomo is used for what the other cores lack (AmneziaWG, pinned
// Hysteria2 certificates); TUIC and WireGuard are supported for overrides.
func mihomoSupports(s *model.Server) error {
	switch s.Protocol {
	case model.AmneziaWG, model.WireGuard, model.Hysteria2, model.TUIC:
		return nil
	}
	return fmt.Errorf("protocol %s is not supported here", s.Protocol)
}

// mihomoConfig builds a mihomo config with a loopback mixed inbound on
// port and srv as the only proxy.
func mihomoConfig(s *model.Server, port int, logLevel string) ([]byte, error) {
	if err := mihomoSupports(s); err != nil {
		return nil, err
	}
	p := map[string]any{"name": "proxy", "server": s.Address, "port": int(s.Port), "udp": true}
	switch s.Protocol {
	case model.WireGuard, model.AmneziaWG:
		wg := s.WireGuard
		p["type"], p["private-key"], p["public-key"] = "wireguard", wg.PrivateKey, wg.PublicKey
		setIf(p, "pre-shared-key", wg.PreSharedKey)
		for _, a := range wg.Addresses {
			ip, _, _ := strings.Cut(a, "/")
			if strings.Contains(ip, ":") {
				p["ipv6"] = ip
			} else {
				p["ip"] = ip
			}
		}
		if len(wg.AllowedIPs) > 0 {
			p["allowed-ips"] = wg.AllowedIPs
		}
		if wg.MTU > 0 {
			p["mtu"] = wg.MTU
		}
		if len(wg.Reserved) > 0 {
			p["reserved"] = wg.Reserved
		}
		if wg.Keepalive > 0 {
			p["persistent-keepalive"] = wg.Keepalive
		}
		if len(wg.Amnezia) > 0 {
			opt := map[string]any{}
			for k, v := range wg.Amnezia {
				if n, err := strconv.Atoi(v); err == nil {
					opt[k] = n
				} else {
					opt[k] = v
				}
			}
			p["amnezia-wg-option"] = opt
		}
	case model.Hysteria2:
		p["type"], p["password"] = "hysteria2", s.Password
		if h := s.Hysteria2; h != nil {
			setIf(p, "ports", h.Ports)
			setIf(p, "obfs", h.Obfs)
			setIf(p, "obfs-password", h.ObfsPassword)
			if h.UpMbps > 0 {
				p["up"] = h.UpMbps
			}
			if h.DownMbps > 0 {
				p["down"] = h.DownMbps
			}
		}
		mihomoTLS(p, s.TLS)
	case model.TUIC:
		p["type"], p["uuid"], p["password"] = "tuic", s.UUID, s.Password
		if t := s.TUIC; t != nil {
			setIf(p, "congestion-controller", t.CongestionControl)
			setIf(p, "udp-relay-mode", t.UDPRelayMode)
			if t.DisableSNI {
				p["disable-sni"] = true
			}
		}
		mihomoTLS(p, s.TLS)
	}
	cfg := map[string]any{
		"mixed-port":      port,
		"bind-address":    "127.0.0.1",
		"allow-lan":       false,
		"mode":            "rule",
		"log-level":       logLevel,
		"ipv6":            true,
		"geo-auto-update": false,
		"profile":         map[string]any{"store-selected": false, "store-fake-ip": false},
		"proxies":         []any{p},
		"rules":           []string{"MATCH,proxy"},
	}
	return yaml.Marshal(cfg)
}

func mihomoTLS(p map[string]any, t *model.TLS) {
	if t == nil {
		return
	}
	setIf(p, "sni", t.SNI)
	if t.Insecure {
		p["skip-cert-verify"] = true
	}
	if len(t.ALPN) > 0 {
		p["alpn"] = t.ALPN
	}
	setIf(p, "fingerprint", t.PinSHA256)
}
