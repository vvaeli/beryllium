package subscription

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vvaeli/beryllium/internal/model"
)

type sbConfig struct {
	Outbounds []sbOutbound `json:"outbounds"`
	Endpoints []sbOutbound `json:"endpoints"`
}

type sbOutbound struct {
	Type        string     `json:"type"`
	Tag         string     `json:"tag"`
	Server      string     `json:"server"`
	ServerPort  int        `json:"server_port"`
	ServerPorts []string   `json:"server_ports"`
	UUID        string     `json:"uuid"`
	Flow        string     `json:"flow"`
	Password    string     `json:"password"`
	Method      string     `json:"method"`
	Security    string     `json:"security"`
	AlterID     int        `json:"alter_id"`
	Plugin      string     `json:"plugin"`
	PluginOpts  string     `json:"plugin_opts"`
	TLS         *sbTLS     `json:"tls"`
	Transport   *sbTrans   `json:"transport"`
	Obfs        *sbObfs    `json:"obfs"`
	UpMbps      int        `json:"up_mbps"`
	DownMbps    int        `json:"down_mbps"`
	Congestion  string     `json:"congestion_control"`
	UDPRelay    string     `json:"udp_relay_mode"`
	PrivateKey  string     `json:"private_key"`
	PeerPubKey  string     `json:"peer_public_key"`
	PreShared   string     `json:"pre_shared_key"`
	LocalAddr   []string   `json:"local_address"`
	Address     []string   `json:"address"`
	MTU         int        `json:"mtu"`
	Reserved    []int      `json:"reserved"`
	Peers       []sbWGPeer `json:"peers"`
}

type sbWGPeer struct {
	Address    string   `json:"address"`
	Port       int      `json:"port"`
	PublicKey  string   `json:"public_key"`
	PreShared  string   `json:"pre_shared_key"`
	AllowedIPs []string `json:"allowed_ips"`
	Reserved   []int    `json:"reserved"`
	Keepalive  int      `json:"persistent_keepalive_interval"`
}

type sbTLS struct {
	Enabled    bool     `json:"enabled"`
	ServerName string   `json:"server_name"`
	Insecure   bool     `json:"insecure"`
	ALPN       []string `json:"alpn"`
	UTLS       *struct {
		Fingerprint string `json:"fingerprint"`
	} `json:"utls"`
	Reality *struct {
		Enabled   bool   `json:"enabled"`
		PublicKey string `json:"public_key"`
		ShortID   string `json:"short_id"`
	} `json:"reality"`
}

type sbTrans struct {
	Type        string            `json:"type"`
	Path        string            `json:"path"`
	Host        json.RawMessage   `json:"host"`
	Headers     map[string]string `json:"headers"`
	ServiceName string            `json:"service_name"`
}

type sbObfs struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

func parseSingBox(body []byte) (Parsed, error) {
	var cfg sbConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return Parsed{}, fmt.Errorf("invalid sing-box config: %w", err)
	}
	var p Parsed
	for i, o := range append(cfg.Outbounds, cfg.Endpoints...) {
		srv, err := singBoxToServer(o)
		if err != nil {
			if !errors.Is(err, errSkip) {
				p.Warnings = append(p.Warnings, fmt.Sprintf("outbound %d: %v", i+1, err))
			}
			continue
		}
		srv.Name = o.Tag
		p.Servers = append(p.Servers, srv)
	}
	return p, nil
}

func singBoxToServer(o sbOutbound) (*model.Server, error) {
	srv := &model.Server{Address: o.Server, UUID: o.UUID, Password: o.Password}
	switch o.Type {
	case "vless":
		srv.Protocol, srv.Flow = model.VLESS, o.Flow
	case "vmess":
		srv.Protocol, srv.AlterID = model.VMess, o.AlterID
		if o.Security != "auto" {
			srv.Method = o.Security
		}
	case "trojan":
		srv.Protocol = model.Trojan
	case "shadowsocks":
		srv.Protocol, srv.Method = model.Shadowsocks, o.Method
		if o.Plugin != "" {
			srv.Plugin = &model.Plugin{Name: o.Plugin, Opts: o.PluginOpts}
		}
	case "hysteria2":
		srv.Protocol = model.Hysteria2
		h := &model.Hysteria2Opts{UpMbps: o.UpMbps, DownMbps: o.DownMbps}
		if o.Obfs != nil {
			h.Obfs, h.ObfsPassword = o.Obfs.Type, o.Obfs.Password
		}
		if len(o.ServerPorts) > 0 {
			h.Ports = joinComma(o.ServerPorts)
		}
		if *h != (model.Hysteria2Opts{}) {
			srv.Hysteria2 = h
		}
	case "tuic":
		srv.Protocol = model.TUIC
		if o.Congestion != "" || o.UDPRelay != "" {
			srv.TUIC = &model.TUICOpts{CongestionControl: o.Congestion, UDPRelayMode: o.UDPRelay}
		}
	case "wireguard":
		return singBoxWireGuard(o)
	case "selector", "urltest", "direct", "block", "dns", "":
		return nil, errSkip
	default:
		return nil, fmt.Errorf("unsupported type %q", o.Type)
	}
	if err := setPort(srv, o.ServerPort); err != nil && srv.Protocol != model.Hysteria2 {
		return nil, err
	} else if srv.Port == 0 {
		srv.Port = 443
	}
	if srv.Address == "" {
		return nil, errors.New("missing server")
	}
	if srv.Protocol == model.VLESS || srv.Protocol == model.VMess || srv.Protocol == model.Trojan {
		srv.Transport = &model.Transport{Type: "tcp"}
		if t := o.Transport; t != nil {
			srv.Transport = &model.Transport{Type: normalizeNetwork(t.Type), Path: t.Path, ServiceName: t.ServiceName,
				Host: sbHost(t)}
		}
	}
	if t := o.TLS; t != nil && t.Enabled {
		tls := &model.TLS{Security: "tls", SNI: t.ServerName, Insecure: t.Insecure, ALPN: t.ALPN}
		if t.UTLS != nil {
			tls.Fingerprint = t.UTLS.Fingerprint
		}
		if t.Reality != nil && t.Reality.Enabled {
			tls.Security, tls.PublicKey, tls.ShortID = "reality", t.Reality.PublicKey, t.Reality.ShortID
		}
		srv.TLS = tls
	}
	return srv, nil
}

func singBoxWireGuard(o sbOutbound) (*model.Server, error) {
	wg := &model.WireGuardOpts{PrivateKey: o.PrivateKey, MTU: o.MTU, Addresses: o.LocalAddr, Reserved: o.Reserved,
		PublicKey: o.PeerPubKey, PreSharedKey: o.PreShared}
	if len(o.Address) > 0 {
		wg.Addresses = o.Address
	}
	srv := &model.Server{Protocol: model.WireGuard, Address: o.Server, WireGuard: wg}
	port := o.ServerPort
	if len(o.Peers) > 0 { // 1.11+ endpoint form
		peer := o.Peers[0]
		srv.Address, port = peer.Address, peer.Port
		wg.PublicKey, wg.PreSharedKey, wg.AllowedIPs, wg.Keepalive = peer.PublicKey, peer.PreShared, peer.AllowedIPs, peer.Keepalive
		if len(peer.Reserved) > 0 {
			wg.Reserved = peer.Reserved
		}
	}
	if err := setPort(srv, port); err != nil {
		return nil, err
	}
	if wg.PrivateKey == "" || wg.PublicKey == "" || srv.Address == "" {
		return nil, errors.New("incomplete wireguard")
	}
	return srv, nil
}

func sbHost(t *sbTrans) string {
	if h := t.Headers["Host"]; h != "" {
		return h
	}
	var s string
	if json.Unmarshal(t.Host, &s) == nil {
		return s
	}
	var list []string
	if json.Unmarshal(t.Host, &list) == nil && len(list) > 0 {
		return list[0]
	}
	return ""
}

func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}
