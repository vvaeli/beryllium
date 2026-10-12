// Package link parses and builds share links (vless://, hy2://, awg:// ...)
// and standalone WireGuard/AmneziaWG configs.
package link

import (
	"errors"
	"fmt"
	"strings"

	"github.com/vvaeli/beryllium/internal/model"
)

// ErrUnsupported is returned for links with an unknown scheme.
var ErrUnsupported = errors.New("unsupported link")

// Parse parses one share link. Errors never include the link itself, so
// they are safe to show and log.
func Parse(s string) (*model.Server, error) {
	s = strings.TrimSpace(s)
	scheme, _, ok := strings.Cut(s, "://")
	if !ok {
		return nil, ErrUnsupported
	}
	var (
		srv *model.Server
		err error
	)
	switch strings.ToLower(scheme) {
	case "vless":
		srv, err = parseXray(s, model.VLESS)
	case "trojan":
		srv, err = parseXray(s, model.Trojan)
	case "vmess":
		srv, err = parseVMess(s)
	case "ss":
		srv, err = parseShadowsocks(s)
	case "hysteria2", "hy2":
		srv, err = parseHysteria2(s)
	case "tuic":
		srv, err = parseTUIC(s)
	case "wireguard", "wg":
		srv, err = parseWireGuardURL(s, false)
	case "awg":
		srv, err = parseWireGuardURL(s, true)
	case "vpn":
		srv, err = parseAmneziaVPN(s)
	default:
		return nil, fmt.Errorf("%w: %s://", ErrUnsupported, strings.ToLower(scheme))
	}
	if err != nil {
		return nil, fmt.Errorf("%s link: %w", strings.ToLower(scheme), err)
	}
	if srv.Country == "" {
		srv.Country = model.CountryFromName(srv.Name)
	}
	return srv, nil
}

// IsRouting reports whether s is a Happ/INCY routing profile link
// (happ://routing/..., incy://routing/..., ://routing/...).
func IsRouting(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	i := strings.Index(s, "://routing/")
	return i >= 0 && (s[:i] == "" || s[:i] == "happ" || s[:i] == "incy")
}

// Encode builds a share link for srv. Parse(Encode(srv)) reproduces srv
// except for ID and Country.
func Encode(srv *model.Server) (string, error) {
	switch srv.Protocol {
	case model.VLESS, model.Trojan:
		return encodeXray(srv), nil
	case model.VMess:
		return encodeVMess(srv)
	case model.Shadowsocks:
		return encodeShadowsocks(srv), nil
	case model.Hysteria2:
		return encodeHysteria2(srv), nil
	case model.TUIC:
		return encodeTUIC(srv), nil
	case model.WireGuard, model.AmneziaWG:
		return encodeWireGuardURL(srv), nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupported, srv.Protocol)
	}
}

func fragment(name string) string {
	if name == "" {
		return ""
	}
	return "#" + escape(name)
}
