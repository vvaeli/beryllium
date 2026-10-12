package link

import (
	"errors"
	"strings"

	"github.com/vvaeli/beryllium/internal/model"
)

// parseXray parses vless:// and trojan:// links (and URL-style vmess://).
func parseXray(s string, proto model.Protocol) (*model.Server, error) {
	u, err := splitURL(s)
	if err != nil {
		return nil, err
	}
	if !u.hasUser || u.user == "" {
		return nil, errors.New("missing user id or password")
	}
	if u.host == "" {
		return nil, errors.New("missing host")
	}
	port, err := parsePort(u.port)
	if err != nil {
		return nil, err
	}
	srv := &model.Server{Name: u.fragment, Protocol: proto, Address: u.host, Port: port}
	switch proto {
	case model.VLESS:
		srv.UUID = u.user
		srv.Flow = u.query.get("flow")
		srv.Encryption = u.query.get("encryption")
		if srv.Encryption == "none" {
			srv.Encryption = ""
		}
	case model.VMess:
		srv.UUID = u.user
		srv.Method = u.query.get("encryption", "scy")
	case model.Trojan:
		srv.Password = u.user
	}
	srv.Transport = transportFromQuery(u.query)
	defaultSec := ""
	if proto == model.Trojan {
		defaultSec = "tls"
	}
	srv.TLS = tlsFromQuery(u.query, defaultSec)
	return srv, nil
}

func normalizeNetwork(n string) string {
	switch strings.ToLower(n) {
	case "", "raw", "tcp":
		return "tcp"
	case "splithttp":
		return "xhttp"
	case "h2":
		return "http"
	default:
		return strings.ToLower(n)
	}
}

func transportFromQuery(q query) *model.Transport {
	t := &model.Transport{
		Type:        normalizeNetwork(q.get("type", "net")),
		Path:        q.get("path"),
		Host:        q.get("host"),
		ServiceName: q.get("servicename", "service_name"),
		HeaderType:  q.get("headertype"),
		Mode:        q.get("mode"),
		Extra:       q.get("extra"),
	}
	if t.HeaderType == "none" {
		t.HeaderType = ""
	}
	if t.Type == "grpc" && t.ServiceName == "" {
		t.ServiceName, t.Path = t.Path, ""
	}
	return t
}

func tlsFromQuery(q query, defaultSec string) *model.TLS {
	sec := strings.ToLower(q.get("security"))
	if sec == "" {
		sec = defaultSec
	}
	if sec == "xtls" {
		sec = "tls"
	}
	if sec != "tls" && sec != "reality" {
		return nil
	}
	return &model.TLS{
		Security:    sec,
		SNI:         q.get("sni", "peer", "servername"),
		ALPN:        splitList(q.get("alpn")),
		Fingerprint: q.get("fp", "fingerprint"),
		Insecure:    q.flag("allowinsecure", "insecure", "allow_insecure"),
		PublicKey:   q.get("pbk", "publickey"),
		ShortID:     q.get("sid", "shortid"),
		SpiderX:     q.get("spx", "spiderx"),
	}
}

func xrayQuery(srv *model.Server) map[string]string {
	q := map[string]string{}
	if t := srv.Transport; t != nil {
		q["type"] = t.Type
		q["path"] = t.Path
		q["host"] = t.Host
		q["serviceName"] = t.ServiceName
		q["headerType"] = t.HeaderType
		q["mode"] = t.Mode
		q["extra"] = t.Extra
	}
	q["security"] = "none"
	if tls := srv.TLS; tls != nil {
		q["security"] = tls.Security
		q["sni"] = tls.SNI
		q["alpn"] = strings.Join(tls.ALPN, ",")
		q["fp"] = tls.Fingerprint
		q["allowInsecure"] = boolStr(tls.Insecure)
		q["pbk"] = tls.PublicKey
		q["sid"] = tls.ShortID
		q["spx"] = tls.SpiderX
	}
	return q
}

func encodeXray(srv *model.Server) string {
	q := xrayQuery(srv)
	user := srv.UUID
	if srv.Protocol == model.Trojan {
		user = srv.Password
	} else {
		q["encryption"] = srv.Encryption
		if q["encryption"] == "" {
			q["encryption"] = "none"
		}
		q["flow"] = srv.Flow
	}
	return string(srv.Protocol) + "://" + escape(user) + "@" + srv.HostPort() + "?" + encodeQuery(q) + fragment(srv.Name)
}
