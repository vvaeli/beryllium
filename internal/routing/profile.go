// Package routing implements routing profiles in the Happ/INCY format and
// translates them, together with the user's rules and DNS settings, into
// the route and dns sections of the sing-box front config.
package routing

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Profile is a Happ/INCY routing profile. Field names follow the Happ JSON
// (https://www.happ.su/main/dev-docs/routing).
type Profile struct {
	Name        string    `json:"name"`
	GlobalProxy bool      `json:"global_proxy"`
	LastUpdated time.Time `json:"last_updated,omitzero"`

	RemoteDNSType     string `json:"remote_dns_type,omitempty"` // DoH or DoU
	RemoteDNSDomain   string `json:"remote_dns_domain,omitempty"`
	RemoteDNSIP       string `json:"remote_dns_ip,omitempty"`
	DomesticDNSType   string `json:"domestic_dns_type,omitempty"`
	DomesticDNSDomain string `json:"domestic_dns_domain,omitempty"`
	DomesticDNSIP     string `json:"domestic_dns_ip,omitempty"`

	DNSHosts       map[string][]string `json:"dns_hosts,omitempty"`
	FakeDNS        bool                `json:"fake_dns,omitempty"`
	DomainStrategy string              `json:"domain_strategy,omitempty"`
	RouteOrder     string              `json:"route_order,omitempty"`

	DirectSites []string `json:"direct_sites,omitempty"`
	DirectIP    []string `json:"direct_ip,omitempty"`
	ProxySites  []string `json:"proxy_sites,omitempty"`
	ProxyIP     []string `json:"proxy_ip,omitempty"`
	BlockSites  []string `json:"block_sites,omitempty"`
	BlockIP     []string `json:"block_ip,omitempty"`

	GeoIPURL   string `json:"geoip_url,omitempty"`
	GeoSiteURL string `json:"geosite_url,omitempty"`
}

// Action of a routing rule.
type Action string

// Rule actions.
const (
	ActionProxy  Action = "proxy"
	ActionDirect Action = "direct"
	ActionBlock  Action = "block"
)

// Order returns the profile's rule groups in evaluation order. RouteOrder
// is e.g. "block-proxy-direct"; missing groups keep that default order.
func (p *Profile) Order() []Action {
	def := []Action{ActionBlock, ActionProxy, ActionDirect}
	var out []Action
	for _, s := range strings.Split(strings.ToLower(p.RouteOrder), "-") {
		a := Action(strings.TrimSpace(s))
		if (a == ActionBlock || a == ActionProxy || a == ActionDirect) && !containsAction(out, a) {
			out = append(out, a)
		}
	}
	for _, a := range def {
		if !containsAction(out, a) {
			out = append(out, a)
		}
	}
	return out
}

func containsAction(as []Action, a Action) bool {
	for _, x := range as {
		if x == a {
			return true
		}
	}
	return false
}

// Lists returns the site and IP lists for an action.
func (p *Profile) Lists(a Action) (sites, ips []string) {
	switch a {
	case ActionProxy:
		return p.ProxySites, p.ProxyIP
	case ActionDirect:
		return p.DirectSites, p.DirectIP
	case ActionBlock:
		return p.BlockSites, p.BlockIP
	}
	return nil, nil
}

// GeoTags returns the geosite and geoip tags the profile refers to.
func (p *Profile) GeoTags() (sites, ips []string) {
	for _, a := range p.Order() {
		s, i := p.Lists(a)
		for _, v := range s {
			if r, err := ParseSiteRule(v); err == nil && r.Kind == SiteGeo {
				sites = appendUnique(sites, r.Tag)
			}
		}
		for _, v := range i {
			if r, err := ParseIPRule(v); err == nil && r.Kind == IPGeo && r.Tag != "private" {
				ips = appendUnique(ips, r.Tag)
			}
		}
	}
	return sites, ips
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// ParseJSON decodes a profile in Happ JSON with Happ's defaults
// (GlobalProxy true, Name "Default"). Keys are matched
// case-insensitively, booleans may be strings ("true"), LastUpdated is
// unix seconds as a string or number, and unknown keys are ignored.
func ParseJSON(data []byte) (*Profile, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), &raw); err != nil {
		return nil, fmt.Errorf("routing profile: %w", err)
	}
	fields := map[string]json.RawMessage{}
	for k, v := range raw {
		fields[strings.ToLower(k)] = v
	}
	p := Profile{GlobalProxy: true}
	d := decoder{fields: fields}
	d.str("name", &p.Name)
	d.boolean("globalproxy", &p.GlobalProxy)
	d.unix("lastupdated", &p.LastUpdated)
	d.str("remotednstype", &p.RemoteDNSType)
	d.str("remotednsdomain", &p.RemoteDNSDomain)
	d.str("remotednsip", &p.RemoteDNSIP)
	if p.RemoteDNSIP == "" {
		d.str("remotedns", &p.RemoteDNSIP)
	}
	d.str("domesticdnstype", &p.DomesticDNSType)
	d.str("domesticdnsdomain", &p.DomesticDNSDomain)
	d.str("domesticdnsip", &p.DomesticDNSIP)
	if p.DomesticDNSIP == "" {
		d.str("domesticdns", &p.DomesticDNSIP)
	}
	d.hosts("dnshosts", &p.DNSHosts)
	d.boolean("fakedns", &p.FakeDNS)
	d.str("domainstrategy", &p.DomainStrategy)
	d.str("routeorder", &p.RouteOrder)
	d.list("directsites", &p.DirectSites)
	d.list("directip", &p.DirectIP)
	d.list("proxysites", &p.ProxySites)
	d.list("proxyip", &p.ProxyIP)
	d.list("blocksites", &p.BlockSites)
	d.list("blockip", &p.BlockIP)
	d.str("geoipurl", &p.GeoIPURL)
	d.str("geositeurl", &p.GeoSiteURL)
	if d.err != nil {
		return nil, fmt.Errorf("routing profile: %w", d.err)
	}
	if p.Name = strings.TrimSpace(p.Name); p.Name == "" {
		p.Name = "Default" // as in Happ and INCY
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks every rule of the profile.
func (p *Profile) Validate() error {
	for _, a := range p.Order() {
		sites, ips := p.Lists(a)
		for _, s := range sites {
			if _, err := ParseSiteRule(s); err != nil {
				return fmt.Errorf("routing profile %q: %w", p.Name, err)
			}
		}
		for _, s := range ips {
			if _, err := ParseIPRule(s); err != nil {
				return fmt.Errorf("routing profile %q: %w", p.Name, err)
			}
		}
	}
	return nil
}

type decoder struct {
	fields map[string]json.RawMessage
	err    error
}

func (d *decoder) get(key string) (json.RawMessage, bool) {
	v, ok := d.fields[key]
	if !ok || d.err != nil || string(v) == "null" {
		return nil, false
	}
	return v, true
}

func (d *decoder) fail(key, want string) {
	if d.err == nil {
		d.err = fmt.Errorf("field %s: expected %s", key, want)
	}
}

func (d *decoder) str(key string, out *string) {
	v, ok := d.get(key)
	if !ok {
		return
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		d.fail(key, "a string")
		return
	}
	*out = strings.TrimSpace(s)
}

func (d *decoder) boolean(key string, out *bool) {
	v, ok := d.get(key)
	if !ok {
		return
	}
	var b bool
	if json.Unmarshal(v, &b) == nil {
		*out = b
		return
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		if b, err := strconv.ParseBool(strings.TrimSpace(s)); err == nil {
			*out = b
			return
		}
	}
	d.fail(key, `true/false or "true"/"false"`)
}

func (d *decoder) unix(key string, out *time.Time) {
	v, ok := d.get(key)
	if !ok {
		return
	}
	var n json.Number
	if json.Unmarshal(v, &n) != nil {
		var s string
		if json.Unmarshal(v, &s) != nil {
			d.fail(key, "unix seconds")
			return
		}
		n = json.Number(strings.TrimSpace(s))
	}
	if n == "" {
		return
	}
	sec, err := n.Int64()
	if err != nil {
		d.fail(key, "unix seconds")
		return
	}
	*out = time.Unix(sec, 0).UTC()
}

func (d *decoder) list(key string, out *[]string) {
	v, ok := d.get(key)
	if !ok {
		return
	}
	var l []string
	if err := json.Unmarshal(v, &l); err != nil {
		d.fail(key, "a list of strings")
		return
	}
	for _, s := range l {
		if s = strings.TrimSpace(s); s != "" {
			*out = append(*out, s)
		}
	}
}

// hosts accepts {"domain": "ip"} or {"domain": ["ip", ...]}.
func (d *decoder) hosts(key string, out *map[string][]string) {
	v, ok := d.get(key)
	if !ok {
		return
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(v, &m); err != nil {
		d.fail(key, "an object")
		return
	}
	res := map[string][]string{}
	for host, raw := range m {
		var one string
		var many []string
		switch {
		case json.Unmarshal(raw, &one) == nil:
			many = strings.Split(one, ",")
		case json.Unmarshal(raw, &many) == nil:
		default:
			d.fail(key, "IP strings")
			return
		}
		for _, ip := range many {
			if ip = strings.TrimSpace(ip); ip != "" {
				res[strings.ToLower(host)] = append(res[strings.ToLower(host)], ip)
			}
		}
	}
	if len(res) > 0 {
		*out = res
	}
}

// MarshalHapp encodes the profile in Happ JSON (string booleans, as Happ
// and INCY export them).
func (p *Profile) MarshalHapp() ([]byte, error) {
	m := map[string]any{
		"Name":          p.Name,
		"GlobalProxy":   strconv.FormatBool(p.GlobalProxy),
		"FakeDNS":       strconv.FormatBool(p.FakeDNS),
		"UseChunkFiles": "false",
		"DirectSites":   orEmpty(p.DirectSites),
		"DirectIp":      orEmpty(p.DirectIP),
		"ProxySites":    orEmpty(p.ProxySites),
		"ProxyIp":       orEmpty(p.ProxyIP),
		"BlockSites":    orEmpty(p.BlockSites),
		"BlockIp":       orEmpty(p.BlockIP),
	}
	set := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	if !p.LastUpdated.IsZero() {
		m["LastUpdated"] = strconv.FormatInt(p.LastUpdated.Unix(), 10)
	}
	set("RemoteDNSType", p.RemoteDNSType)
	set("RemoteDNSDomain", p.RemoteDNSDomain)
	set("RemoteDNSIP", p.RemoteDNSIP)
	set("DomesticDNSType", p.DomesticDNSType)
	set("DomesticDNSDomain", p.DomesticDNSDomain)
	set("DomesticDNSIP", p.DomesticDNSIP)
	set("DomainStrategy", p.DomainStrategy)
	set("RouteOrder", p.RouteOrder)
	set("Geoipurl", p.GeoIPURL)
	set("Geositeurl", p.GeoSiteURL)
	if len(p.DNSHosts) > 0 {
		h := map[string]string{}
		for k, v := range p.DNSHosts {
			h[k] = strings.Join(v, ",")
		}
		m["DnsHosts"] = h
	}
	return json.Marshal(m)
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Link encodes the profile as happ://routing/onadd/<base64>, which Happ,
// INCY and Beryllium import.
func (p *Profile) Link() (string, error) {
	raw, err := p.MarshalHapp()
	if err != nil {
		return "", err
	}
	return "happ://routing/onadd/" + base64.StdEncoding.EncodeToString(raw), nil
}

// Decoded is a profile decoded from a link or header.
type Decoded struct {
	Profile *Profile
	// Immediate is true for onadd links and bare base64/JSON: activate at
	// once. add links activate once the geo files are downloaded (INCY).
	Immediate bool
}

// Decode reads a profile from a deeplink ({happ,incy,...}://routing/
// {add,onadd}/<base64>), bare base64 (the `routing` subscription header)
// or raw JSON. Errors never echo the input.
func Decode(s string) (*Decoded, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") {
		p, err := ParseJSON([]byte(s))
		if err != nil {
			return nil, err
		}
		return &Decoded{Profile: p, Immediate: true}, nil
	}
	immediate := true
	payload := s
	if _, rest, ok := strings.Cut(s, "://"); ok {
		rest = strings.TrimPrefix(rest, "/")
		parts := strings.SplitN(rest, "/", 3)
		if len(parts) < 3 || !strings.EqualFold(parts[0], "routing") {
			return nil, errors.New("routing link: expected <scheme>://routing/add|onadd/<base64>")
		}
		switch strings.ToLower(parts[1]) {
		case "onadd":
		case "add":
			immediate = false
		default:
			return nil, fmt.Errorf("routing link: unsupported action %q", parts[1])
		}
		payload = parts[2]
	}
	raw, err := decodeBase64(payload)
	if err != nil {
		return nil, errors.New("routing link: payload is not valid base64")
	}
	p, err := ParseJSON(raw)
	if err != nil {
		return nil, err
	}
	return &Decoded{Profile: p, Immediate: immediate}, nil
}

// decodeBase64 accepts standard and URL-safe alphabets, with or without
// padding, and ignores whitespace and URL-escaped padding.
func decodeBase64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	if strings.Contains(s, "%") {
		if u, err := url.PathUnescape(s); err == nil {
			s = u
		}
	}
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "-_") {
		return base64.RawURLEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}
