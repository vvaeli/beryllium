package subscription

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/vvaeli/beryllium/internal/model"
)

type xrayConfig struct {
	Remarks   string         `json:"remarks"`
	Outbounds []xrayOutbound `json:"outbounds"`
}

type xrayOutbound struct {
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"`
	Settings       xraySettings    `json:"settings"`
	StreamSettings *xrayStream     `json:"streamSettings"`
	Raw            json.RawMessage `json:"-"`
}

type xraySettings struct {
	Vnext []struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
		Users   []struct {
			ID         string `json:"id"`
			Flow       string `json:"flow"`
			Encryption string `json:"encryption"`
			AlterID    int    `json:"alterId"`
			Security   string `json:"security"`
		} `json:"users"`
	} `json:"vnext"`
	Servers []struct {
		Address  string `json:"address"`
		Port     int    `json:"port"`
		Password string `json:"password"`
		Method   string `json:"method"`
	} `json:"servers"`
}

type xrayStream struct {
	Network         string `json:"network"`
	Security        string `json:"security"`
	RealitySettings *struct {
		ServerName  string `json:"serverName"`
		Fingerprint string `json:"fingerprint"`
		PublicKey   string `json:"publicKey"`
		ShortID     string `json:"shortId"`
		SpiderX     string `json:"spiderX"`
	} `json:"realitySettings"`
	TLSSettings *struct {
		ServerName    string   `json:"serverName"`
		Fingerprint   string   `json:"fingerprint"`
		ALPN          []string `json:"alpn"`
		AllowInsecure bool     `json:"allowInsecure"`
	} `json:"tlsSettings"`
	WSSettings *struct {
		Path    string            `json:"path"`
		Host    string            `json:"host"`
		Headers map[string]string `json:"headers"`
	} `json:"wsSettings"`
	GRPCSettings *struct {
		ServiceName string `json:"serviceName"`
		MultiMode   bool   `json:"multiMode"`
	} `json:"grpcSettings"`
	XHTTPSettings *struct {
		Path  string          `json:"path"`
		Host  string          `json:"host"`
		Mode  string          `json:"mode"`
		Extra json.RawMessage `json:"extra"`
	} `json:"xhttpSettings"`
	HTTPUpgradeSettings *struct {
		Path string `json:"path"`
		Host string `json:"host"`
	} `json:"httpupgradeSettings"`
	TCPSettings *struct {
		Header *struct {
			Type string `json:"type"`
		} `json:"header"`
	} `json:"tcpSettings"`
}

// parseXrayConfig extracts proxy outbounds from one Xray config.
func parseXrayConfig(body []byte) (Parsed, error) {
	var cfg xrayConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return Parsed{}, fmt.Errorf("invalid Xray config: %w", err)
	}
	var p Parsed
	for i, o := range cfg.Outbounds {
		srv, err := xrayOutboundToServer(o)
		if err != nil {
			if !errors.Is(err, errSkip) {
				p.Warnings = append(p.Warnings, fmt.Sprintf("outbound %d: %v", i+1, err))
			}
			continue
		}
		srv.Name = cfg.Remarks
		if o.Tag != "" && o.Tag != "proxy" {
			if srv.Name == "" {
				srv.Name = o.Tag
			} else {
				srv.Name += " " + o.Tag
			}
		}
		p.Servers = append(p.Servers, srv)
	}
	return p, nil
}

var errSkip = errors.New("not a proxy outbound")

func xrayOutboundToServer(o xrayOutbound) (*model.Server, error) {
	srv := &model.Server{}
	switch o.Protocol {
	case "vless", "vmess":
		if len(o.Settings.Vnext) == 0 || len(o.Settings.Vnext[0].Users) == 0 {
			return nil, errors.New("missing vnext")
		}
		v, u := o.Settings.Vnext[0], o.Settings.Vnext[0].Users[0]
		srv.Address, srv.UUID = v.Address, u.ID
		if err := setPort(srv, v.Port); err != nil {
			return nil, err
		}
		if o.Protocol == "vless" {
			srv.Protocol, srv.Flow = model.VLESS, u.Flow
			if u.Encryption != "none" {
				srv.Encryption = u.Encryption
			}
		} else {
			srv.Protocol, srv.AlterID = model.VMess, u.AlterID
			if u.Security != "auto" {
				srv.Method = u.Security
			}
		}
	case "trojan", "shadowsocks":
		if len(o.Settings.Servers) == 0 {
			return nil, errors.New("missing servers")
		}
		s := o.Settings.Servers[0]
		srv.Address, srv.Password = s.Address, s.Password
		if err := setPort(srv, s.Port); err != nil {
			return nil, err
		}
		if o.Protocol == "trojan" {
			srv.Protocol = model.Trojan
		} else {
			srv.Protocol, srv.Method = model.Shadowsocks, s.Method
			return srv, nil
		}
	case "freedom", "blackhole", "dns", "loopback", "":
		return nil, errSkip
	default:
		return nil, fmt.Errorf("unsupported protocol %q", o.Protocol)
	}
	applyXrayStream(srv, o.StreamSettings)
	return srv, nil
}

func setPort(srv *model.Server, port int) error {
	if port <= 0 || port > 65535 {
		return errors.New("bad port " + strconv.Itoa(port))
	}
	srv.Port = uint16(port)
	return nil
}

func applyXrayStream(srv *model.Server, st *xrayStream) {
	t := &model.Transport{Type: "tcp"}
	srv.Transport = t
	if st == nil {
		return
	}
	t.Type = normalizeNetwork(st.Network)
	switch {
	case st.WSSettings != nil && t.Type == "ws":
		t.Path, t.Host = st.WSSettings.Path, st.WSSettings.Host
		if t.Host == "" {
			t.Host = st.WSSettings.Headers["Host"]
		}
	case st.GRPCSettings != nil && t.Type == "grpc":
		t.ServiceName = st.GRPCSettings.ServiceName
		if st.GRPCSettings.MultiMode {
			t.Mode = "multi"
		}
	case st.XHTTPSettings != nil && t.Type == "xhttp":
		t.Path, t.Host, t.Mode = st.XHTTPSettings.Path, st.XHTTPSettings.Host, st.XHTTPSettings.Mode
		if len(st.XHTTPSettings.Extra) > 0 && string(st.XHTTPSettings.Extra) != "null" {
			t.Extra = string(st.XHTTPSettings.Extra)
		}
	case st.HTTPUpgradeSettings != nil && t.Type == "httpupgrade":
		t.Path, t.Host = st.HTTPUpgradeSettings.Path, st.HTTPUpgradeSettings.Host
	case st.TCPSettings != nil && st.TCPSettings.Header != nil && st.TCPSettings.Header.Type != "none":
		t.HeaderType = st.TCPSettings.Header.Type
	}
	switch st.Security {
	case "reality":
		tls := &model.TLS{Security: "reality"}
		if r := st.RealitySettings; r != nil {
			tls.SNI, tls.Fingerprint, tls.PublicKey, tls.ShortID, tls.SpiderX = r.ServerName, r.Fingerprint, r.PublicKey, r.ShortID, r.SpiderX
		}
		srv.TLS = tls
	case "tls":
		tls := &model.TLS{Security: "tls"}
		if s := st.TLSSettings; s != nil {
			tls.SNI, tls.Fingerprint, tls.ALPN, tls.Insecure = s.ServerName, s.Fingerprint, s.ALPN, s.AllowInsecure
		}
		srv.TLS = tls
	}
}

func normalizeNetwork(n string) string {
	switch n {
	case "", "raw", "tcp":
		return "tcp"
	case "splithttp":
		return "xhttp"
	case "h2":
		return "http"
	}
	return n
}
