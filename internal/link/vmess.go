package link

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/vvaeli/beryllium/internal/model"
)

// vmessJSON is the v2rayN vmess:// payload. Numbers may be strings or numbers.
type vmessJSON struct {
	V    flexString `json:"v"`
	PS   string     `json:"ps"`
	Add  string     `json:"add"`
	Port flexString `json:"port"`
	ID   string     `json:"id"`
	Aid  flexString `json:"aid"`
	Scy  string     `json:"scy"`
	Net  string     `json:"net"`
	Type string     `json:"type"`
	Host string     `json:"host"`
	Path string     `json:"path"`
	TLS  string     `json:"tls"`
	SNI  string     `json:"sni"`
	ALPN string     `json:"alpn"`
	FP   string     `json:"fp"`
	// Insecure is not part of the v2rayN format but some panels add it.
	Insecure flexString `json:"allowInsecure,omitempty"`
}

type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		var bl bool
		if json.Unmarshal(b, &bl) == nil {
			*f = flexString(strconv.FormatBool(bl))
			return nil
		}
		return err
	}
	*f = flexString(n.String())
	return nil
}

func parseVMess(s string) (*model.Server, error) {
	payload := strings.TrimSpace(s[len("vmess://"):])
	raw, err := decodeBase64(payload)
	if err != nil {
		// Some clients emit URL-style vmess links.
		return parseXray(s, model.VMess)
	}
	var j vmessJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil, errors.New("bad JSON payload")
	}
	port, err := parsePort(string(j.Port))
	if err != nil {
		return nil, err
	}
	if j.ID == "" || j.Add == "" {
		return nil, errors.New("missing id or address")
	}
	aid, _ := strconv.Atoi(string(j.Aid))
	srv := &model.Server{
		Name: j.PS, Protocol: model.VMess, Address: j.Add, Port: port,
		UUID: j.ID, AlterID: aid, Method: j.Scy,
	}
	if srv.Method == "auto" {
		srv.Method = ""
	}
	q := query{"type": j.Net, "host": j.Host, "path": j.Path, "headertype": j.Type,
		"security": j.TLS, "sni": j.SNI, "alpn": j.ALPN, "fp": j.FP, "allowinsecure": string(j.Insecure)}
	srv.Transport = transportFromQuery(q)
	srv.TLS = tlsFromQuery(q, "")
	return srv, nil
}

func encodeVMess(srv *model.Server) (string, error) {
	j := vmessJSON{
		V: "2", PS: srv.Name, Add: srv.Address, Port: flexString(strconv.Itoa(int(srv.Port))),
		ID: srv.UUID, Aid: flexString(strconv.Itoa(srv.AlterID)), Scy: srv.Method, Net: "tcp",
	}
	if j.Scy == "" {
		j.Scy = "auto"
	}
	if t := srv.Transport; t != nil {
		j.Net, j.Host, j.Path, j.Type = t.Type, t.Host, t.Path, t.HeaderType
		if t.Type == "grpc" {
			j.Path = t.ServiceName
		}
	}
	if j.Type == "" {
		j.Type = "none"
	}
	if tls := srv.TLS; tls != nil {
		j.TLS, j.SNI, j.ALPN, j.FP = tls.Security, tls.SNI, strings.Join(tls.ALPN, ","), tls.Fingerprint
		if tls.Insecure {
			j.Insecure = "1"
		}
	}
	raw, err := json.Marshal(j)
	if err != nil {
		return "", err
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(raw), nil
}

// decodeBase64 accepts standard and URL-safe alphabets, with or without
// padding, ignoring whitespace.
func decodeBase64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "-_") {
		return base64.RawURLEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}
