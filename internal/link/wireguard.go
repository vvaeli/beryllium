package link

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/vvaeli/beryllium/internal/model"
)

// parseWireGuardURL parses wireguard://, wg:// and awg:// links:
//
//	wireguard://<private key>@host:port?publickey=..&address=..&mtu=..&reserved=1,2,3#name
//
// awg:// is the same with AmneziaWG parameters (jc, jmin, ...) in the query.
func parseWireGuardURL(s string, amnezia bool) (*model.Server, error) {
	u, err := splitURL(s)
	if err != nil {
		return nil, err
	}
	port, err := parsePort(u.port)
	if err != nil {
		return nil, err
	}
	wg := &model.WireGuardOpts{
		PrivateKey:   u.user,
		PublicKey:    u.query.get("publickey", "public_key", "peer_public_key"),
		PreSharedKey: u.query.get("presharedkey", "pre_shared_key", "psk"),
		Addresses:    splitList(u.query.get("address", "ip", "local_address")),
		AllowedIPs:   splitList(u.query.get("allowedips", "allowed_ips")),
		DNS:          splitList(u.query.get("dns")),
	}
	wg.MTU, _ = strconv.Atoi(u.query.get("mtu"))
	wg.Keepalive, _ = strconv.Atoi(u.query.get("keepalive", "persistentkeepalive"))
	for _, r := range splitList(u.query.get("reserved")) {
		n, err := strconv.Atoi(r)
		if err != nil {
			return nil, errors.New("bad reserved")
		}
		wg.Reserved = append(wg.Reserved, n)
	}
	for _, k := range model.AmneziaKeys {
		if v, ok := u.query[k]; ok && v != "" {
			if wg.Amnezia == nil {
				wg.Amnezia = map[string]string{}
			}
			wg.Amnezia[k] = v
		}
	}
	return finishWireGuard(u.fragment, u.host, port, wg, amnezia)
}

func finishWireGuard(name, host string, port uint16, wg *model.WireGuardOpts, amnezia bool) (*model.Server, error) {
	if wg.PrivateKey == "" || wg.PublicKey == "" || host == "" {
		return nil, errors.New("missing private key, peer public key or endpoint")
	}
	proto := model.WireGuard
	if amnezia || len(wg.Amnezia) > 0 {
		proto = model.AmneziaWG
	}
	return &model.Server{Name: name, Protocol: proto, Address: host, Port: port, WireGuard: wg}, nil
}

func encodeWireGuardURL(srv *model.Server) string {
	wg := srv.WireGuard
	q := map[string]string{}
	if wg != nil {
		q["publickey"] = wg.PublicKey
		q["presharedkey"] = wg.PreSharedKey
		q["address"] = strings.Join(wg.Addresses, ",")
		q["allowedips"] = strings.Join(wg.AllowedIPs, ",")
		q["dns"] = strings.Join(wg.DNS, ",")
		q["mtu"] = itoa(wg.MTU)
		q["keepalive"] = itoa(wg.Keepalive)
		var res []string
		for _, r := range wg.Reserved {
			res = append(res, strconv.Itoa(r))
		}
		q["reserved"] = strings.Join(res, ",")
		for k, v := range wg.Amnezia {
			q[k] = v
		}
	}
	scheme := "wireguard"
	if srv.Protocol == model.AmneziaWG {
		scheme = "awg"
	}
	key := ""
	if wg != nil {
		key = wg.PrivateKey
	}
	return scheme + "://" + escape(key) + "@" + srv.HostPort() + "?" + encodeQuery(q) + fragment(srv.Name)
}

// ParseWireGuardConf parses a wg-quick style config (.conf). AmneziaWG
// parameters in [Interface] make it an AmneziaWG server. Only the first
// [Peer] is used.
func ParseWireGuardConf(text, name string) (*model.Server, error) {
	wg := &model.WireGuardOpts{}
	var section, endpoint string
	peers := 0
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i == 0 {
			continue
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			if section == "peer" {
				peers++
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch {
		case section == "interface" && k == "privatekey":
			wg.PrivateKey = v
		case section == "interface" && k == "address":
			wg.Addresses = splitList(v)
		case section == "interface" && k == "dns":
			wg.DNS = splitList(v)
		case section == "interface" && k == "mtu":
			wg.MTU, _ = strconv.Atoi(v)
		case section == "interface" && model.IsAmneziaKey(k):
			if wg.Amnezia == nil {
				wg.Amnezia = map[string]string{}
			}
			wg.Amnezia[k] = v
		case section == "peer" && peers == 1 && k == "publickey":
			wg.PublicKey = v
		case section == "peer" && peers == 1 && k == "presharedkey":
			wg.PreSharedKey = v
		case section == "peer" && peers == 1 && k == "allowedips":
			wg.AllowedIPs = splitList(v)
		case section == "peer" && peers == 1 && k == "endpoint":
			endpoint = v
		case section == "peer" && peers == 1 && k == "persistentkeepalive":
			wg.Keepalive, _ = strconv.Atoi(v)
		}
	}
	if endpoint == "" {
		return nil, errors.New("wireguard config: missing [Peer] Endpoint")
	}
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, errors.New("wireguard config: bad Endpoint")
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}
	srv, err := finishWireGuard(name, host, port, wg, false)
	if err != nil {
		return nil, errors.New("wireguard config: " + err.Error())
	}
	srv.Country = model.CountryFromName(name)
	return srv, nil
}

// parseAmneziaVPN decodes an Amnezia VPN share string: vpn:// followed by
// URL-safe base64 of Qt qCompress output (4-byte big-endian length + zlib)
// wrapping a JSON document whose AWG/WireGuard container holds a wg-quick
// config.
func parseAmneziaVPN(s string) (*model.Server, error) {
	raw, err := decodeBase64(s[len("vpn://"):])
	if err != nil || len(raw) < 5 {
		return nil, errors.New("bad payload")
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw[4:]))
	if err != nil {
		return nil, errors.New("bad compressed payload")
	}
	data, err := io.ReadAll(io.LimitReader(zr, 1<<20))
	if err != nil {
		return nil, errors.New("bad compressed payload")
	}
	var doc struct {
		Description string `json:"description"`
		HostName    string `json:"hostName"`
		Containers  []map[string]json.RawMessage
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, errors.New("bad JSON payload")
	}
	name := doc.Description
	if name == "" {
		name = doc.HostName
	}
	for _, c := range doc.Containers {
		for _, key := range []string{"awg", "wireguard"} {
			proto, ok := c[key]
			if !ok {
				continue
			}
			var p struct {
				LastConfig string `json:"last_config"`
			}
			if json.Unmarshal(proto, &p) != nil || p.LastConfig == "" {
				continue
			}
			var lc struct {
				Config string `json:"config"`
			}
			if json.Unmarshal([]byte(p.LastConfig), &lc) != nil || lc.Config == "" {
				continue
			}
			srv, err := ParseWireGuardConf(lc.Config, name)
			if err != nil {
				return nil, err
			}
			if key == "awg" {
				srv.Protocol = model.AmneziaWG
			}
			return srv, nil
		}
	}
	return nil, errors.New("no AmneziaWG or WireGuard container (other Amnezia protocols are not supported)")
}
