package routing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Outbound tags of the sing-box front config.
const (
	TagProxy  = "proxy"
	TagDirect = "direct"
)

// Defaults for DNS when neither settings nor the profile set a resolver.
const (
	DefaultRemoteDNS = "https://1.1.1.1/dns-query"
	// Empty direct DNS means the system resolver.
	DefaultDirectDNS = ""
)

// UserRule is a rule from settings, evaluated before the active profile.
type UserRule struct {
	Match  Match  `json:"match"`
	Value  string `json:"value"`
	Action Action `json:"action"`
}

// Match is the matcher of a user rule.
type Match string

// User rule matchers.
const (
	MatchDomain        Match = "domain"
	MatchDomainSuffix  Match = "domain_suffix"
	MatchDomainKeyword Match = "domain_keyword"
	MatchIPCIDR        Match = "ip_cidr"
	MatchProcessName   Match = "process_name"
	MatchProcessPath   Match = "process_path"
)

// Validate checks a user rule.
func (r UserRule) Validate() error {
	if strings.TrimSpace(r.Value) == "" {
		return errors.New("rule value is empty")
	}
	switch r.Action {
	case ActionProxy, ActionDirect, ActionBlock:
	default:
		return fmt.Errorf("unknown rule action %q", r.Action)
	}
	switch r.Match {
	case MatchDomain, MatchDomainSuffix, MatchDomainKeyword, MatchProcessName, MatchProcessPath:
	case MatchIPCIDR:
		if ir, err := ParseIPRule(r.Value); err != nil || ir.Kind != IPCIDR {
			return fmt.Errorf("%q is not an IP or CIDR", r.Value)
		}
	default:
		return fmt.Errorf("unknown rule match %q", r.Match)
	}
	return nil
}

// DNS settings that override the profile's resolvers.
type DNS struct {
	// Remote resolver for proxied domains (DoH URL, tls://, udp:// or IP);
	// empty uses the profile's, then DefaultRemoteDNS.
	Remote string
	// Direct resolver; empty uses the profile's, then the system resolver.
	Direct string
	FakeIP bool
	// IPv6 tunnels IPv6; otherwise IPv6 is rejected and DNS returns only A
	// records, so nothing leaks around a server without IPv6.
	IPv6 bool
}

// Input is everything a Plan is built from.
type Input struct {
	// Profile is the active profile; nil proxies everything.
	Profile *Profile
	// GeoSite and GeoIP are local .dat files for the profile's geo tags.
	GeoSite, GeoIP string
	Rules          []UserRule
	DNS            DNS
	// TUN enables DNS hijacking-related options (FakeIP only works in TUN).
	TUN bool
	// RuleSetDir caches compiled rule-sets.
	RuleSetDir string
	// Compile turns a source rule-set (JSON) into a binary .srs file;
	// nil keeps source rule-sets.
	Compile func(src, dst string) error
}

// Plan holds the parts of the sing-box config that routing owns.
type Plan struct {
	// Rules go after the core's own rules (sniff, DNS hijack, loop
	// prevention).
	Rules    []any
	RuleSets []any
	Final    string
	DNS      map[string]any
	// Warnings are non-fatal problems, e.g. a geo tag missing from the file.
	Warnings []string
}

// Build translates in into a Plan. Order: IPv6 policy, user rules, LAN
// direct, the profile's groups in RouteOrder, then final.
func Build(in Input) (*Plan, error) {
	b := &builder{in: in, plan: &Plan{Final: TagProxy}, ruleSets: map[string]bool{}}
	if p := in.Profile; p != nil && !p.GlobalProxy {
		b.plan.Final = TagDirect
	}
	if err := b.loadGeo(); err != nil {
		return nil, err
	}
	b.routeRules()
	if err := b.dns(); err != nil {
		return nil, err
	}
	return b.plan, nil
}

type builder struct {
	in       Input
	plan     *Plan
	sites    map[string][]SiteEntry
	ips      map[string]IPList
	siteHash string
	ipHash   string
	ruleSets map[string]bool
}

func (b *builder) warn(format string, args ...any) {
	if w := fmt.Sprintf(format, args...); !slices.Contains(b.plan.Warnings, w) {
		b.plan.Warnings = append(b.plan.Warnings, w)
	}
}

// loadGeo reads only the tags the profile uses, and only when a compiled
// rule-set for them is not cached yet.
func (b *builder) loadGeo() error {
	p := b.in.Profile
	if p == nil {
		return nil
	}
	siteTags, ipTags := p.GeoTags()
	load := func(path string, tags []string, hash *string, read func([]byte) error) error {
		if len(tags) == 0 {
			return nil
		}
		if path == "" {
			b.warn("geo files for %s are not downloaded", strings.Join(tags, ", "))
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("geo data: %w", err)
		}
		sum := sha256.Sum256(data)
		*hash = hex.EncodeToString(sum[:8])
		return read(data)
	}
	err := load(b.in.GeoSite, siteTags, &b.siteHash, func(data []byte) (err error) {
		b.sites, err = ReadGeoSite(data, siteTags)
		return err
	})
	if err != nil {
		return err
	}
	return load(b.in.GeoIP, ipTags, &b.ipHash, func(data []byte) (err error) {
		b.ips, err = ReadGeoIP(data, ipTags)
		return err
	})
}

func outbound(a Action) map[string]any {
	switch a {
	case ActionBlock:
		return map[string]any{"action": "reject"}
	case ActionDirect:
		return map[string]any{"action": "route", "outbound": TagDirect}
	default:
		return map[string]any{"action": "route", "outbound": TagProxy}
	}
}

func withAction(m map[string]any, a Action) map[string]any {
	for k, v := range outbound(a) {
		m[k] = v
	}
	return m
}

func (b *builder) routeRules() {
	add := func(r map[string]any) { b.plan.Rules = append(b.plan.Rules, r) }
	if !b.in.DNS.IPv6 {
		add(map[string]any{"ip_version": 6, "action": "reject"})
	}
	// The user's rules win over everything else, then LAN and private
	// networks always go direct.
	for _, r := range b.in.Rules {
		v := strings.TrimSpace(r.Value)
		if r.Match == MatchIPCIDR {
			if ir, err := ParseIPRule(v); err == nil {
				v = ir.Prefix.String()
			}
		}
		add(withAction(map[string]any{string(r.Match): []string{v}}, r.Action))
	}
	add(map[string]any{"ip_is_private": true, "action": "route", "outbound": TagDirect})
	add(map[string]any{"domain_suffix": []string{"local", "localhost", "lan", "home.arpa"}, "action": "route", "outbound": TagDirect})

	p := b.in.Profile
	if p == nil {
		return
	}
	var ipRules []map[string]any
	for _, a := range p.Order() {
		sites, ips := p.Lists(a)
		if r := b.siteRule(sites); r != nil {
			add(withAction(r, a))
		}
		for _, r := range b.ipRules(ips) {
			ipRules = append(ipRules, withAction(r, a))
		}
	}
	if len(ipRules) == 0 {
		return
	}
	// AsIs (the default) matches IP rules only against connections that
	// already carry an IP, e.g. from TUN. IPIfNonMatch checks domain rules
	// first, then resolves and checks IP rules; IPOnDemand resolves first.
	resolve := map[string]any{"action": "resolve"}
	if !b.in.DNS.IPv6 {
		resolve["strategy"] = "ipv4_only"
	}
	switch strings.ToLower(p.DomainStrategy) {
	case "ipifnonmatch":
		add(resolve)
	case "ipondemand":
		b.plan.Rules = slices.Insert(b.plan.Rules, b.firstProfileRule(), any(resolve))
	}
	for _, r := range ipRules {
		add(r)
	}
}

// firstProfileRule is the index of the first rule after the fixed and
// user rules.
func (b *builder) firstProfileRule() int {
	n := 2 + len(b.in.Rules)
	if !b.in.DNS.IPv6 {
		n++
	}
	return min(n, len(b.plan.Rules))
}

// siteRule merges domain rules of one group into a single sing-box rule
// (its domain items are ORed). nil when nothing remains.
func (b *builder) siteRule(sites []string) map[string]any {
	r := map[string]any{}
	appendTo := func(k, v string) {
		l, _ := r[k].([]string)
		if !slices.Contains(l, v) {
			r[k] = append(l, v)
		}
	}
	for _, s := range sites {
		sr, err := ParseSiteRule(s)
		if err != nil {
			continue // Validate rejected these at import
		}
		switch sr.Kind {
		case SiteGeo:
			if tag := b.geoSiteSet(sr); tag != "" {
				appendTo("rule_set", tag)
			}
		case SiteSuffix:
			appendTo("domain_suffix", sr.Value)
		case SiteFull:
			appendTo("domain", sr.Value)
		case SiteRegex:
			appendTo("domain_regex", sr.Value)
		case SiteKeyword:
			appendTo("domain_keyword", sr.Value)
		}
	}
	if len(r) == 0 {
		return nil
	}
	return r
}

func (b *builder) ipRules(ips []string) []map[string]any {
	r := map[string]any{}
	var private []map[string]any
	for _, s := range ips {
		ir, err := ParseIPRule(s)
		if err != nil {
			continue
		}
		switch {
		case ir.Kind == IPCIDR:
			l, _ := r["ip_cidr"].([]string)
			r["ip_cidr"] = append(l, ir.Prefix.String())
		case ir.Tag == "private" && !ir.Invert:
			private = append(private, map[string]any{"ip_is_private": true})
		default:
			if tag := b.geoIPSet(ir); tag != "" {
				l, _ := r["rule_set"].([]string)
				r["rule_set"] = append(l, tag)
			}
		}
	}
	if len(r) > 0 {
		private = append(private, r)
	}
	return private
}

// geoSiteSet registers a rule-set for a geosite tag and returns its tag.
func (b *builder) geoSiteSet(sr SiteRule) string {
	name := "geosite-" + sr.Tag
	if sr.Attr != "" {
		name += "@" + sr.Attr
	}
	if b.ruleSets[name] {
		return name
	}
	entries, ok := b.sites[sr.Tag]
	if !ok {
		b.warn("geosite:%s is not in the geosite file", sr.Tag)
		return ""
	}
	rule := map[string]any{}
	for _, e := range entries {
		if sr.Attr != "" && !slices.Contains(e.Attrs, sr.Attr) {
			continue
		}
		var k string
		switch e.Type {
		case domainFull:
			k = "domain"
		case domainSuffix:
			k = "domain_suffix"
		case domainRegex:
			k = "domain_regex"
		default:
			k = "domain_keyword"
		}
		l, _ := rule[k].([]string)
		rule[k] = append(l, e.Value)
	}
	if len(rule) == 0 {
		b.warn("geosite:%s has no entries", strings.TrimPrefix(name, "geosite-"))
		return ""
	}
	return b.addRuleSet(name, b.siteHash, rule)
}

func (b *builder) geoIPSet(ir IPRule) string {
	name := "geoip-" + ir.Tag
	if ir.Invert {
		name = "geoip-not-" + ir.Tag
	}
	if b.ruleSets[name] {
		return name
	}
	l, ok := b.ips[ir.Tag]
	if !ok {
		b.warn("geoip:%s is not in the geoip file", ir.Tag)
		return ""
	}
	cidrs := make([]string, 0, len(l.CIDRs))
	for _, p := range l.CIDRs {
		cidrs = append(cidrs, p.String())
	}
	if len(cidrs) == 0 {
		b.warn("geoip:%s has no entries", ir.Tag)
		return ""
	}
	rule := map[string]any{"ip_cidr": cidrs}
	if l.Reverse != ir.Invert {
		rule["invert"] = true
	}
	return b.addRuleSet(name, b.ipHash, rule)
}

// addRuleSet writes (and compiles) a rule-set file named after the geo
// file hash and tag, reusing it when it already exists.
func (b *builder) addRuleSet(name, fileHash string, rule map[string]any) string {
	h := sha256.Sum256([]byte(fileHash + "\x00" + name))
	base := filepath.Join(b.in.RuleSetDir, hex.EncodeToString(h[:10]))
	src, bin := base+".json", base+".srs"
	format, path := "binary", bin
	if b.in.Compile == nil {
		format, path = "source", src
	}
	if _, err := os.Stat(path); err != nil {
		if err := b.writeRuleSet(src, bin, rule); err != nil {
			b.warn("rule-set %s: %v", name, err)
			return ""
		}
	}
	b.ruleSets[name] = true
	b.plan.RuleSets = append(b.plan.RuleSets, map[string]any{"type": "local", "tag": name, "format": format, "path": path})
	return name
}

func (b *builder) writeRuleSet(src, bin string, rule map[string]any) error {
	if err := os.MkdirAll(b.in.RuleSetDir, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(map[string]any{"version": 3, "rules": []any{rule}})
	if err != nil {
		return err
	}
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		return err
	}
	if b.in.Compile == nil {
		return nil
	}
	tmp := bin + ".tmp"
	if err := b.in.Compile(src, tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	os.Remove(src)
	return os.Rename(tmp, bin)
}

// DNS tags.
const (
	dnsLocal  = "local"
	dnsRemote = "remote"
	dnsDirect = "direct-dns"
	dnsHosts  = "hosts"
	dnsFakeIP = "fakeip"
)

func (b *builder) dns() error {
	p := b.in.Profile
	if p == nil {
		p = &Profile{GlobalProxy: true}
	}
	remote := b.in.DNS.Remote
	if remote == "" {
		remote = profileDNS(p.RemoteDNSType, p.RemoteDNSDomain, p.RemoteDNSIP)
	}
	if remote == "" {
		remote = DefaultRemoteDNS
	}
	direct := b.in.DNS.Direct
	if direct == "" {
		direct = profileDNS(p.DomesticDNSType, p.DomesticDNSDomain, p.DomesticDNSIP)
	}

	remoteSrv, err := dnsServer(remote, dnsRemote)
	if err != nil {
		return fmt.Errorf("remote DNS: %w", err)
	}
	remoteSrv["detour"] = TagProxy
	directSrv := map[string]any{"type": "local", "tag": dnsDirect}
	if direct != "" {
		if directSrv, err = dnsServer(direct, dnsDirect); err != nil {
			return fmt.Errorf("direct DNS: %w", err)
		}
	}
	servers := []any{map[string]any{"type": "local", "tag": dnsLocal}, remoteSrv, directSrv}
	var rules []any

	if len(p.DNSHosts) > 0 {
		hosts := map[string]any{}
		var domains []string
		for host, ips := range p.DNSHosts {
			hosts[host] = ips
			domains = append(domains, host)
		}
		slices.Sort(domains)
		servers = append(servers, map[string]any{"type": "hosts", "tag": dnsHosts, "predefined": hosts})
		rules = append(rules, map[string]any{"domain": domains, "server": dnsHosts})
	}

	// Domains follow their traffic: direct ones are resolved by the direct
	// resolver so CDNs answer with nearby addresses, proxied ones by the
	// remote resolver through the tunnel.
	dnsRule := func(r map[string]any, a Action) {
		switch a {
		case ActionBlock:
			r["action"] = "reject"
		case ActionDirect:
			r["server"] = dnsDirect
		default:
			r["server"] = dnsRemote
		}
		rules = append(rules, r)
	}
	dnsRule(map[string]any{"domain_suffix": []string{"local", "localhost", "lan", "home.arpa"}}, ActionDirect)
	for _, r := range b.in.Rules {
		switch r.Match {
		case MatchDomain, MatchDomainSuffix, MatchDomainKeyword:
			dnsRule(map[string]any{string(r.Match): []string{strings.TrimSpace(r.Value)}}, r.Action)
		}
	}
	if b.in.Profile != nil {
		for _, a := range p.Order() {
			sites, _ := p.Lists(a)
			if r := b.siteRule(sites); r != nil {
				dnsRule(r, a)
			}
		}
	}

	final := dnsRemote
	if !p.GlobalProxy {
		final = dnsDirect
	}
	if (b.in.DNS.FakeIP || p.FakeDNS) && b.in.TUN {
		servers = append(servers, map[string]any{
			"type": "fakeip", "tag": dnsFakeIP, "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18",
		})
		if final == dnsRemote {
			rules = append(rules, map[string]any{"query_type": []string{"A", "AAAA"}, "server": dnsFakeIP})
		}
	}
	b.plan.DNS = map[string]any{"servers": servers, "rules": rules, "final": final}
	if !b.in.DNS.IPv6 {
		b.plan.DNS["strategy"] = "ipv4_only"
	}
	return nil
}

// profileDNS picks the resolver of a profile: DoH uses the URL, DoU the IP.
func profileDNS(typ, domain, ip string) string {
	switch strings.ToLower(typ) {
	case "doh":
		if domain != "" {
			return domain
		}
	case "dou":
		if ip != "" {
			return ip
		}
	}
	if domain != "" && strings.Contains(domain, "://") {
		return domain
	}
	return ip
}

// dnsServer converts a resolver spec into a sing-box DNS server:
// https://host/path, h3://, tls://host, quic://host, tcp://ip, udp://ip, or
// a bare IP (UDP). Hostnames are resolved by the local (system) resolver.
func dnsServer(spec, tag string) (map[string]any, error) {
	spec = strings.TrimSpace(spec)
	if !strings.Contains(spec, "://") {
		spec = "udp://" + spec
	}
	u, err := url.Parse(spec)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid resolver %q", spec)
	}
	typ := strings.ToLower(u.Scheme)
	switch typ {
	case "https", "h3", "tls", "quic", "tcp", "udp":
	default:
		return nil, fmt.Errorf("unsupported resolver scheme %s://", typ)
	}
	s := map[string]any{"type": typ, "tag": tag, "server": u.Hostname()}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil {
			return nil, fmt.Errorf("invalid resolver port %q", port)
		}
		s["server_port"] = n
	}
	if (typ == "https" || typ == "h3") && u.Path != "" && u.Path != "/dns-query" {
		s["path"] = u.Path
	}
	if _, err := netip.ParseAddr(u.Hostname()); err != nil {
		s["domain_resolver"] = dnsLocal
	}
	return s, nil
}

// ValidateResolver checks a DNS resolver spec as accepted in settings.
func ValidateResolver(spec string) error {
	_, err := dnsServer(spec, "check")
	return err
}

// PruneRuleSets deletes compiled rule-sets in dir that plan doesn't use,
// so files of replaced geo data don't pile up.
func PruneRuleSets(dir string, plan *Plan) {
	keep := map[string]bool{}
	if plan != nil {
		for _, rs := range plan.RuleSets {
			if m, ok := rs.(map[string]any); ok {
				if p, ok := m["path"].(string); ok {
					keep[filepath.Base(p)] = true
				}
			}
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !keep[e.Name()] {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
