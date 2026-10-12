// Package model is the core-agnostic description of proxy servers. Parsers
// produce it; core config translators (ROADMAP phase 5) consume it.
package model

import (
	"strconv"
	"strings"
)

// Protocol identifies the proxy protocol.
type Protocol string

// Supported protocols.
const (
	VLESS       Protocol = "vless"
	VMess       Protocol = "vmess"
	Trojan      Protocol = "trojan"
	Shadowsocks Protocol = "shadowsocks"
	Hysteria2   Protocol = "hysteria2"
	TUIC        Protocol = "tuic"
	WireGuard   Protocol = "wireguard"
	AmneziaWG   Protocol = "amneziawg"
)

// Server is one proxy endpoint with everything needed to connect.
// It contains credentials and must never be logged as a whole.
type Server struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Country  string   `json:"country,omitempty"`
	Protocol Protocol `json:"protocol"`
	Address  string   `json:"address"`
	Port     uint16   `json:"port"`

	// UUID is the user id (VLESS, VMess, TUIC).
	UUID string `json:"uuid,omitempty"`
	// Password (Trojan, Shadowsocks, Hysteria2, TUIC).
	Password string `json:"password,omitempty"`
	// Method is the Shadowsocks cipher or the VMess security ("auto", ...).
	Method string `json:"method,omitempty"`
	// Flow is the VLESS flow, e.g. "xtls-rprx-vision".
	Flow string `json:"flow,omitempty"`
	// Encryption is the VLESS encryption ("none" unless post-quantum).
	Encryption string `json:"encryption,omitempty"`
	AlterID    int    `json:"alter_id,omitempty"`

	Transport *Transport     `json:"transport,omitempty"`
	TLS       *TLS           `json:"tls,omitempty"`
	Plugin    *Plugin        `json:"plugin,omitempty"`
	Hysteria2 *Hysteria2Opts `json:"hysteria2,omitempty"`
	TUIC      *TUICOpts      `json:"tuic,omitempty"`
	WireGuard *WireGuardOpts `json:"wireguard,omitempty"`
}

// Transport is the Xray-style stream transport (VLESS, VMess, Trojan).
type Transport struct {
	// Type: tcp, ws, grpc, http (h2), httpupgrade, xhttp, kcp, quic.
	Type        string `json:"type"`
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	// HeaderType is the tcp/kcp header obfuscation, e.g. "http".
	HeaderType string `json:"header_type,omitempty"`
	// Mode is the xhttp mode or the grpc mode ("gun", "multi").
	Mode string `json:"mode,omitempty"`
	// Extra is the raw xhttp "extra" JSON.
	Extra string `json:"extra,omitempty"`
}

// TLS describes TLS or REALITY. Absent means no transport security.
type TLS struct {
	// Security is "tls" or "reality".
	Security    string   `json:"security"`
	SNI         string   `json:"sni,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Insecure    bool     `json:"insecure,omitempty"`
	// REALITY parameters.
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
	SpiderX   string `json:"spider_x,omitempty"`
	// PinSHA256 pins the certificate (Hysteria2).
	PinSHA256 string `json:"pin_sha256,omitempty"`
}

// Plugin is a Shadowsocks SIP003 plugin.
type Plugin struct {
	Name string `json:"name"`
	Opts string `json:"opts,omitempty"`
}

// Hysteria2Opts are Hysteria2 options.
type Hysteria2Opts struct {
	Obfs         string `json:"obfs,omitempty"`
	ObfsPassword string `json:"obfs_password,omitempty"`
	// Ports is a port-hopping spec such as "443,20000-30000".
	Ports    string `json:"ports,omitempty"`
	UpMbps   int    `json:"up_mbps,omitempty"`
	DownMbps int    `json:"down_mbps,omitempty"`
}

// TUICOpts are TUIC v5 options.
type TUICOpts struct {
	CongestionControl string `json:"congestion_control,omitempty"`
	UDPRelayMode      string `json:"udp_relay_mode,omitempty"`
	DisableSNI        bool   `json:"disable_sni,omitempty"`
}

// WireGuardOpts holds WireGuard and AmneziaWG parameters.
type WireGuardOpts struct {
	PrivateKey   string   `json:"private_key"`
	PublicKey    string   `json:"public_key"`
	PreSharedKey string   `json:"pre_shared_key,omitempty"`
	Addresses    []string `json:"addresses,omitempty"`
	AllowedIPs   []string `json:"allowed_ips,omitempty"`
	DNS          []string `json:"dns,omitempty"`
	MTU          int      `json:"mtu,omitempty"`
	Reserved     []int    `json:"reserved,omitempty"`
	Keepalive    int      `json:"keepalive,omitempty"`
	// Amnezia holds AmneziaWG obfuscation parameters keyed by their
	// lowercase names (jc, jmin, jmax, s1–s4, h1–h4, i1–i5, j1–j3, itime).
	// Values are kept as strings: AWG 2.0 allows ranges such as "100-200".
	Amnezia map[string]string `json:"amnezia,omitempty"`
}

// AmneziaKeys lists the known AmneziaWG parameters in canonical order.
var AmneziaKeys = []string{
	"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
	"i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3", "itime",
}

// IsAmneziaKey reports whether k (any case) is an AmneziaWG parameter.
func IsAmneziaKey(k string) bool {
	k = strings.ToLower(k)
	for _, a := range AmneziaKeys {
		if a == k {
			return true
		}
	}
	return false
}

// Key identifies the server's endpoint and identity, ignoring its display
// name, so that IDs stay stable across subscription refreshes.
func (s *Server) Key() string {
	parts := []string{string(s.Protocol), s.Address, strconv.Itoa(int(s.Port)), s.UUID, s.Password}
	if s.Transport != nil {
		parts = append(parts, s.Transport.Type, s.Transport.Path, s.Transport.ServiceName)
	}
	if s.TLS != nil {
		parts = append(parts, s.TLS.Security, s.TLS.SNI)
	}
	if s.WireGuard != nil {
		parts = append(parts, s.WireGuard.PublicKey, s.WireGuard.PrivateKey)
	}
	return strings.Join(parts, "|")
}

// HostPort formats Address:Port, bracketing IPv6 literals.
func (s *Server) HostPort() string {
	host := s.Address
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(int(s.Port))
}
