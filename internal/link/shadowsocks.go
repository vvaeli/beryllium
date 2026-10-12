package link

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/vvaeli/beryllium/internal/model"
)

// parseShadowsocks handles SIP002 (ss://base64(method:pass)@host:port,
// ss://method:pass@host:port for 2022 ciphers) and the legacy
// ss://base64(method:pass@host:port) form.
func parseShadowsocks(s string) (*model.Server, error) {
	body := s[len("ss://"):]
	name := ""
	if i := strings.IndexByte(body, '#'); i >= 0 {
		name = unescape(body[i+1:])
		body = body[:i]
	}
	if !strings.Contains(body, "@") {
		plain := body
		if i := strings.IndexAny(plain, "/?"); i >= 0 {
			plain = plain[:i]
		}
		raw, err := decodeBase64(plain)
		if err != nil {
			return nil, errors.New("bad legacy payload")
		}
		body = string(raw)
	}
	u, err := splitURL("ss://" + body)
	if err != nil {
		return nil, err
	}
	method, pass, ok := strings.Cut(u.user, ":")
	if !ok {
		raw, err := decodeBase64(u.user)
		if err != nil {
			return nil, errors.New("bad user info")
		}
		if method, pass, ok = strings.Cut(string(raw), ":"); !ok {
			return nil, errors.New("bad user info")
		}
	}
	port, err := parsePort(u.port)
	if err != nil {
		return nil, err
	}
	if u.host == "" || method == "" {
		return nil, errors.New("missing host or method")
	}
	srv := &model.Server{Name: name, Protocol: model.Shadowsocks, Address: u.host, Port: port,
		Method: method, Password: pass}
	if p := u.query.get("plugin"); p != "" {
		pn, opts, _ := strings.Cut(p, ";")
		srv.Plugin = &model.Plugin{Name: pn, Opts: opts}
	}
	return srv, nil
}

func encodeShadowsocks(srv *model.Server) string {
	var user string
	if strings.HasPrefix(srv.Method, "2022-") {
		user = escape(srv.Method) + ":" + escape(srv.Password)
	} else {
		user = base64.RawURLEncoding.EncodeToString([]byte(srv.Method + ":" + srv.Password))
	}
	out := "ss://" + user + "@" + srv.HostPort()
	if srv.Plugin != nil {
		p := srv.Plugin.Name
		if srv.Plugin.Opts != "" {
			p += ";" + srv.Plugin.Opts
		}
		out += "/?" + encodeQuery(map[string]string{"plugin": p})
	}
	return out + fragment(srv.Name)
}
