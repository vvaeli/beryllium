package link

import (
	"errors"
	"strconv"
	"strings"

	"github.com/vvaeli/beryllium/internal/model"
)

func parseHysteria2(s string) (*model.Server, error) {
	u, err := splitURL(s)
	if err != nil {
		return nil, err
	}
	if u.host == "" {
		return nil, errors.New("missing host")
	}
	srv := &model.Server{Name: u.fragment, Protocol: model.Hysteria2, Address: u.host, Password: u.user}
	opts := &model.Hysteria2Opts{
		Obfs:         u.query.get("obfs"),
		ObfsPassword: u.query.get("obfs-password", "obfs_password"),
		Ports:        u.query.get("mport", "ports"),
	}
	opts.UpMbps, _ = strconv.Atoi(u.query.get("upmbps", "up"))
	opts.DownMbps, _ = strconv.Atoi(u.query.get("downmbps", "down"))
	// The port part may be a hopping spec: "443,20000-30000".
	first := u.port
	if i := strings.IndexAny(first, ",-"); i >= 0 {
		if opts.Ports == "" {
			opts.Ports = u.port
		}
		first = first[:i]
	}
	if first == "" {
		first = "443"
	}
	if srv.Port, err = parsePort(first); err != nil {
		return nil, err
	}
	if *opts != (model.Hysteria2Opts{}) {
		srv.Hysteria2 = opts
	}
	srv.TLS = &model.TLS{
		Security:  "tls",
		SNI:       u.query.get("sni", "peer"),
		ALPN:      splitList(u.query.get("alpn")),
		Insecure:  u.query.flag("insecure", "allowinsecure"),
		PinSHA256: u.query.get("pinsha256"),
	}
	return srv, nil
}

func encodeHysteria2(srv *model.Server) string {
	q := map[string]string{}
	if tls := srv.TLS; tls != nil {
		q["sni"] = tls.SNI
		q["alpn"] = strings.Join(tls.ALPN, ",")
		q["insecure"] = boolStr(tls.Insecure)
		q["pinSHA256"] = tls.PinSHA256
	}
	if h := srv.Hysteria2; h != nil {
		q["obfs"] = h.Obfs
		q["obfs-password"] = h.ObfsPassword
		q["mport"] = h.Ports
		q["upmbps"] = itoa(h.UpMbps)
		q["downmbps"] = itoa(h.DownMbps)
	}
	user := ""
	if srv.Password != "" {
		user = escape(srv.Password) + "@"
	}
	return "hysteria2://" + user + srv.HostPort() + "/?" + encodeQuery(q) + fragment(srv.Name)
}

func parseTUIC(s string) (*model.Server, error) {
	u, err := splitURL(s)
	if err != nil {
		return nil, err
	}
	id, pass, ok := strings.Cut(u.user, ":")
	if !ok || id == "" || u.host == "" {
		return nil, errors.New("missing uuid:password or host")
	}
	port, err := parsePort(u.port)
	if err != nil {
		return nil, err
	}
	srv := &model.Server{Name: u.fragment, Protocol: model.TUIC, Address: u.host, Port: port, UUID: id, Password: pass}
	opts := &model.TUICOpts{
		CongestionControl: u.query.get("congestion_control", "congestion-control"),
		UDPRelayMode:      u.query.get("udp_relay_mode", "udp-relay-mode"),
		DisableSNI:        u.query.flag("disable_sni", "disable-sni"),
	}
	if *opts != (model.TUICOpts{}) {
		srv.TUIC = opts
	}
	srv.TLS = &model.TLS{
		Security: "tls",
		SNI:      u.query.get("sni"),
		ALPN:     splitList(u.query.get("alpn")),
		Insecure: u.query.flag("allow_insecure", "allowinsecure", "insecure"),
	}
	return srv, nil
}

func encodeTUIC(srv *model.Server) string {
	q := map[string]string{}
	if tls := srv.TLS; tls != nil {
		q["sni"] = tls.SNI
		q["alpn"] = strings.Join(tls.ALPN, ",")
		q["allow_insecure"] = boolStr(tls.Insecure)
	}
	if t := srv.TUIC; t != nil {
		q["congestion_control"] = t.CongestionControl
		q["udp_relay_mode"] = t.UDPRelayMode
		q["disable_sni"] = boolStr(t.DisableSNI)
	}
	return "tuic://" + escape(srv.UUID) + ":" + escape(srv.Password) + "@" + srv.HostPort() + "?" + encodeQuery(q) + fragment(srv.Name)
}
