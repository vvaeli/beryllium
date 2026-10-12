package routing

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// --- synthetic geo files -------------------------------------------------

type siteFixture struct {
	typ   int
	value string
	attrs []string
}

func geoSiteDat(tags map[string][]siteFixture) []byte {
	var list []byte
	for tag, domains := range tags {
		var site []byte
		site = protowire.AppendTag(site, 1, protowire.BytesType)
		site = protowire.AppendString(site, strings.ToUpper(tag))
		for _, d := range domains {
			var dom []byte
			dom = protowire.AppendTag(dom, 1, protowire.VarintType)
			dom = protowire.AppendVarint(dom, uint64(d.typ))
			dom = protowire.AppendTag(dom, 2, protowire.BytesType)
			dom = protowire.AppendString(dom, d.value)
			for _, a := range d.attrs {
				var attr []byte
				attr = protowire.AppendTag(attr, 1, protowire.BytesType)
				attr = protowire.AppendString(attr, a)
				attr = protowire.AppendTag(attr, 2, protowire.VarintType)
				attr = protowire.AppendVarint(attr, 1)
				dom = protowire.AppendTag(dom, 3, protowire.BytesType)
				dom = protowire.AppendBytes(dom, attr)
			}
			site = protowire.AppendTag(site, 2, protowire.BytesType)
			site = protowire.AppendBytes(site, dom)
		}
		list = protowire.AppendTag(list, 1, protowire.BytesType)
		list = protowire.AppendBytes(list, site)
	}
	return list
}

func geoIPDat(tags map[string][]string) []byte {
	var list []byte
	for tag, cidrs := range tags {
		var geo []byte
		geo = protowire.AppendTag(geo, 1, protowire.BytesType)
		geo = protowire.AppendString(geo, strings.ToUpper(tag))
		for _, c := range cidrs {
			p := netip.MustParsePrefix(c)
			var cidr []byte
			cidr = protowire.AppendTag(cidr, 1, protowire.BytesType)
			cidr = protowire.AppendBytes(cidr, p.Addr().AsSlice())
			cidr = protowire.AppendTag(cidr, 2, protowire.VarintType)
			cidr = protowire.AppendVarint(cidr, uint64(p.Bits()))
			geo = protowire.AppendTag(geo, 2, protowire.BytesType)
			geo = protowire.AppendBytes(geo, cidr)
		}
		list = protowire.AppendTag(list, 1, protowire.BytesType)
		list = protowire.AppendBytes(list, geo)
	}
	return list
}

var testSites = map[string][]siteFixture{
	"category-ru":  {{domainSuffix, "yandex.ru", nil}, {domainFull, "vk.com", nil}, {domainPlain, "sber", nil}, {domainRegex, `^gos\.`, nil}},
	"google":       {{domainSuffix, "google.com", nil}, {domainSuffix, "doubleclick.net", []string{"ads"}}},
	"category-ads": {{domainSuffix, "ads.example", nil}},
}

var testIPs = map[string][]string{
	"ru":     {"5.8.0.0/16", "2a00:1450::/32"},
	"direct": {"77.88.0.0/18"},
}

func TestGeoDat(t *testing.T) {
	sites, err := ReadGeoSite(geoSiteDat(testSites), []string{"CATEGORY-RU", "google", "missing"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sites["category-ru"]) != 4 || len(sites["google"]) != 2 || sites["missing"] != nil {
		t.Fatalf("sites = %+v", sites)
	}
	if got := sites["google"][1]; got.Value != "doubleclick.net" || got.Type != domainSuffix || !reflect.DeepEqual(got.Attrs, []string{"ads"}) {
		t.Errorf("entry = %+v", got)
	}
	ips, err := ReadGeoIP(geoIPDat(testIPs), []string{"ru"})
	if err != nil {
		t.Fatal(err)
	}
	if got := ips["ru"].CIDRs; len(got) != 2 || got[0].String() != "5.8.0.0/16" || got[1].String() != "2a00:1450::/32" {
		t.Errorf("ru = %v", got)
	}
	if _, err := ReadGeoIP([]byte{0x0a, 0xff}, nil); err == nil {
		t.Error("truncated file parsed")
	}
}

// --- profiles ---------------------------------------------------------

func TestFixtures(t *testing.T) {
	files, _ := filepath.Glob("testdata/roscomvpn/*.json")
	if len(files) == 0 {
		t.Fatal("no fixtures")
	}
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		p, err := ParseJSON(raw)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if !p.GlobalProxy || p.LastUpdated.IsZero() || p.RemoteDNSDomain == "" || p.GeoSiteURL == "" || len(p.DNSHosts) != 2 {
			t.Errorf("%s: %+v", f, p)
		}
		link, _ := os.ReadFile(strings.TrimSuffix(f, ".json") + ".deeplink")
		dec, err := Decode(string(link))
		if err != nil {
			t.Fatalf("%s deeplink: %v", f, err)
		}
		if !dec.Immediate || !reflect.DeepEqual(dec.Profile, p) {
			t.Errorf("%s: deeplink differs from JSON", f)
		}
		// Our own export must round-trip.
		out, err := p.Link()
		if err != nil {
			t.Fatal(err)
		}
		back, err := Decode(out)
		if err != nil || !reflect.DeepEqual(back.Profile, p) {
			t.Errorf("%s: round trip: %v\n%+v\n%+v", f, err, back.Profile, p)
		}
	}
	raw, _ := os.ReadFile("testdata/roscomvpn/happ-default.json")
	p, _ := ParseJSON(raw)
	if got := p.Order(); !reflect.DeepEqual(got, []Action{ActionBlock, ActionProxy, ActionDirect}) {
		t.Errorf("order = %v", got)
	}
	sites, ips := p.GeoTags()
	if len(sites) != 20 || !reflect.DeepEqual(ips, []string{"direct"}) {
		t.Errorf("geo tags = %v %v", sites, ips)
	}
}

func TestParseJSONTypes(t *testing.T) {
	p, err := ParseJSON([]byte(`{"name":" X ","GlobalProxy":false,"LastUpdated":1700000000,"FakeDNS":"TRUE",
		"DnsHosts":{"A.example":["1.1.1.1","2.2.2.2"]},"RemoteDns":"9.9.9.9","Unknown":{"x":1},"DirectSites":null}`))
	if err != nil {
		t.Fatal(err)
	}
	want := &Profile{Name: "X", GlobalProxy: false, LastUpdated: time.Unix(1700000000, 0).UTC(), FakeDNS: true,
		DNSHosts: map[string][]string{"a.example": {"1.1.1.1", "2.2.2.2"}}, RemoteDNSIP: "9.9.9.9"}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("got %+v", p)
	}
	p, err = ParseJSON([]byte(`{}`))
	if err != nil || p.Name != "Default" || !p.GlobalProxy {
		t.Errorf("defaults: %+v %v", p, err)
	}
	for _, bad := range []string{
		`{"GlobalProxy":"maybe"}`,
		`{"DirectSites":"geosite:ru"}`,
		`{"LastUpdated":"yesterday"}`,
		`{"DirectSites":["ext:custom.dat:ru"]}`,
		`{"DirectIp":["not-an-ip"]}`,
		`{"BlockSites":["regexp:("]}`,
		`[1]`,
	} {
		if _, err := ParseJSON([]byte(bad)); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}

func TestDecode(t *testing.T) {
	js := `{"Name":"T","DirectSites":["domain:ru"]}`
	payloads := map[string]string{
		"std":     base64.StdEncoding.EncodeToString([]byte(js)),
		"raw":     base64.RawStdEncoding.EncodeToString([]byte(js)),
		"url":     base64.URLEncoding.EncodeToString([]byte(js)),
		"rawurl":  base64.RawURLEncoding.EncodeToString([]byte(js)),
		"escaped": strings.ReplaceAll(base64.StdEncoding.EncodeToString([]byte(js)), "=", "%3D"),
	}
	for name, b64 := range payloads {
		for _, in := range []string{
			"happ://routing/onadd/" + b64,
			"incy://routing/onadd/" + b64,
			"://routing/onadd/" + b64,
			b64,
		} {
			d, err := Decode(in)
			if err != nil || d.Profile.Name != "T" || !d.Immediate {
				t.Errorf("%s %q: %+v %v", name, in, d, err)
			}
		}
	}
	d, err := Decode("happ://routing/add/" + payloads["std"])
	if err != nil || d.Immediate {
		t.Errorf("add: %+v %v", d, err)
	}
	if d, err := Decode(js); err != nil || d.Profile.Name != "T" {
		t.Errorf("json: %v", err)
	}
	secret := "happ://routing/onadd/c2VjcmV0LXRva2Vu"
	for _, bad := range []string{"happ://routing/off/" + payloads["std"], "happ://sub/x/y", secret, "!!!"} {
		_, err := Decode(bad)
		if err == nil {
			t.Errorf("%q: no error", bad)
		} else if strings.Contains(err.Error(), "c2VjcmV0") {
			t.Errorf("error echoes input: %v", err)
		}
	}
}

func TestRules(t *testing.T) {
	sites := map[string]SiteRule{
		"geosite:Category-RU":  {Kind: SiteGeo, Tag: "category-ru"},
		"geosite:google@ads":   {Kind: SiteGeo, Tag: "google", Attr: "ads"},
		"domain:.Example.com":  {Kind: SiteSuffix, Value: "example.com"},
		"full:www.example.com": {Kind: SiteFull, Value: "www.example.com"},
		"regexp:^ads[0-9]+\\.": {Kind: SiteRegex, Value: "^ads[0-9]+\\."},
		"keyword:tracker":      {Kind: SiteKeyword, Value: "tracker"},
		"youtube":              {Kind: SiteKeyword, Value: "youtube"},
	}
	for in, want := range sites {
		got, err := ParseSiteRule(in)
		if err != nil || got != want {
			t.Errorf("%q = %+v %v, want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "domain:", "ext:x.dat:y", "geosite:!ru", "foo:bar", "regexp:("} {
		if _, err := ParseSiteRule(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
	ips := map[string]IPRule{
		"geoip:RU":      {Kind: IPGeo, Tag: "ru"},
		"geoip:!ru":     {Kind: IPGeo, Tag: "ru", Invert: true},
		"10.1.2.3/8":    {Kind: IPCIDR, Prefix: netip.MustParsePrefix("10.0.0.0/8")},
		"1.1.1.1":       {Kind: IPCIDR, Prefix: netip.MustParsePrefix("1.1.1.1/32")},
		"2001:db8::/32": {Kind: IPCIDR, Prefix: netip.MustParsePrefix("2001:db8::/32")},
		"geoip:private": {Kind: IPGeo, Tag: "private"},
	}
	for in, want := range ips {
		got, err := ParseIPRule(in)
		if err != nil || got != want {
			t.Errorf("%q = %+v %v, want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"geoip:", "ext:a:b", "example.com", "300.1.1.1"} {
		if _, err := ParseIPRule(bad); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

// --- plan -------------------------------------------------------------

func writeGeo(t *testing.T) (site, ip string) {
	dir := t.TempDir()
	site, ip = filepath.Join(dir, "geosite.dat"), filepath.Join(dir, "geoip.dat")
	if err := os.WriteFile(site, geoSiteDat(testSites), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ip, geoIPDat(testIPs), 0o600); err != nil {
		t.Fatal(err)
	}
	return site, ip
}

func toJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestBuild(t *testing.T) {
	site, ip := writeGeo(t)
	p := &Profile{
		Name: "T", GlobalProxy: true, RouteOrder: "direct-block-proxy", DomainStrategy: "IPIfNonMatch",
		DirectSites:   []string{"geosite:category-ru", "domain:ru", "geosite:missing"},
		DirectIP:      []string{"geoip:private", "geoip:ru", "192.0.2.0/24"},
		BlockSites:    []string{"geosite:google@ads", "keyword:tracker"},
		ProxySites:    []string{"full:x.ru"},
		DNSHosts:      map[string][]string{"h.example": {"1.2.3.4"}},
		RemoteDNSType: "DoH", RemoteDNSDomain: "https://dns.google/dns-query",
		DomesticDNSType: "DoU", DomesticDNSIP: "77.88.8.8",
	}
	in := Input{
		Profile: p, GeoSite: site, GeoIP: ip, RuleSetDir: t.TempDir(),
		Rules: []UserRule{{Match: MatchDomainSuffix, Value: "corp.example", Action: ActionDirect}, {Match: MatchIPCIDR, Value: "203.0.113.7", Action: ActionBlock}},
	}
	plan, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	rules := toJSON(t, plan.Rules)
	if pre := toJSON(t, plan.PreRules); pre != `[{"action":"reject","mode":"and","rules":[{"ip_version":6},{"invert":true,"port":53}],"type":"logical"}]` {
		t.Errorf("pre rules = %s", pre)
	}
	want := []string{
		`{"action":"route","domain_suffix":["corp.example"],"outbound":"direct"}`,
		`{"action":"reject","ip_cidr":["203.0.113.7/32"]}`,
		`{"action":"route","ip_is_private":true,"outbound":"direct"}`,
		`{"action":"route","domain_suffix":["ru"],"outbound":"direct","rule_set":["geosite-category-ru"]}`,
		`{"action":"reject","domain_keyword":["tracker"],"rule_set":["geosite-google@ads"]}`,
		`{"action":"route","domain":["x.ru"],"outbound":"proxy"}`,
		`{"action":"resolve","strategy":"ipv4_only"}`,
		`{"action":"route","ip_cidr":["192.0.2.0/24"],"outbound":"direct","rule_set":["geoip-ru"]}`,
	}
	last := -1
	for _, w := range want {
		i := strings.Index(rules, w)
		if i < 0 || i < last {
			t.Fatalf("rule %s missing or out of order in\n%s", w, rules)
		}
		last = i
	}
	if plan.Final != TagProxy || len(plan.RuleSets) != 3 {
		t.Errorf("final %s, rule sets %s", plan.Final, toJSON(t, plan.RuleSets))
	}
	if len(plan.Warnings) != 1 || !strings.Contains(plan.Warnings[0], "geosite:missing") {
		t.Errorf("warnings = %v", plan.Warnings)
	}
	// The ads attribute keeps only doubleclick.net.
	for _, rs := range plan.RuleSets {
		m := rs.(map[string]any)
		raw, _ := os.ReadFile(m["path"].(string))
		if m["tag"] == "geosite-google@ads" && (!strings.Contains(string(raw), "doubleclick.net") || strings.Contains(string(raw), `"google.com"`)) {
			t.Errorf("attr filter: %s", raw)
		}
	}
	dns := toJSON(t, plan.DNS)
	for _, w := range []string{
		`"server":"dns.google","tag":"remote","type":"https"`,
		`"domain_resolver":"local"`,
		`"server":"77.88.8.8","tag":"direct-dns","type":"udp"`,
		`{"domain":["h.example"],"server":"hosts"}`,
		`"final":"remote"`,
		`"strategy":"ipv4_only"`,
	} {
		if !strings.Contains(dns, w) {
			t.Errorf("dns lacks %s:\n%s", w, dns)
		}
	}

	// Rule-sets are cached by content.
	plan2, err := Build(in)
	if err != nil || toJSON(t, plan2.RuleSets) != toJSON(t, plan.RuleSets) {
		t.Errorf("rebuild differs: %v", err)
	}

	// No profile: everything proxied, IPv6 allowed when asked.
	plan, err = Build(Input{DNS: DNS{IPv6: true, Remote: "tls://1.1.1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.PreRules) != 0 || plan.Final != TagProxy || plan.DNS["strategy"] != nil {
		t.Errorf("plain plan: %s", toJSON(t, plan))
	}

	// GlobalProxy=false: final and DNS final are direct, FakeIP only in TUN.
	p2 := &Profile{Name: "D", GlobalProxy: false, ProxySites: []string{"domain:blocked.example"}, FakeDNS: true}
	plan, _ = Build(Input{Profile: p2})
	if plan.Final != TagDirect || plan.DNS["final"] != "direct-dns" || strings.Contains(toJSON(t, plan.DNS), "fakeip") {
		t.Errorf("direct plan: %s", toJSON(t, plan))
	}
	plan, _ = Build(Input{Profile: &Profile{Name: "F", GlobalProxy: true}, DNS: DNS{FakeIP: true}, TUN: true})
	if !strings.Contains(toJSON(t, plan.DNS), `"server":"fakeip"`) {
		t.Errorf("fakeip missing: %s", toJSON(t, plan.DNS))
	}
}

func TestDNSServer(t *testing.T) {
	for in, want := range map[string]string{
		"1.1.1.1":                    `{"server":"1.1.1.1","tag":"t","type":"udp"}`,
		"https://1.1.1.1/dns-query":  `{"server":"1.1.1.1","tag":"t","type":"https"}`,
		"https://dns.example:8443/q": `{"domain_resolver":"local","path":"/q","server":"dns.example","server_port":8443,"tag":"t","type":"https"}`,
		"tls://[2606:4700::1111]":    `{"server":"2606:4700::1111","tag":"t","type":"tls"}`,
	} {
		got, err := dnsServer(in, "t")
		if err != nil || toJSON(t, got) != want {
			t.Errorf("%s = %s %v", in, toJSON(t, got), err)
		}
	}
	for _, bad := range []string{"sdns://x", "https://", ""} {
		if _, err := dnsServer(bad, "t"); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestUserRuleValidate(t *testing.T) {
	ok := []UserRule{{MatchDomain, "a.com", ActionProxy}, {MatchIPCIDR, "10.0.0.0/8", ActionBlock}, {MatchProcessName, "Telegram", ActionDirect}}
	for _, r := range ok {
		if err := r.Validate(); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	bad := []UserRule{{MatchDomain, " ", ActionProxy}, {MatchIPCIDR, "geoip:ru", ActionProxy}, {"port", "1", ActionProxy}, {MatchDomain, "a", "drop"}}
	for _, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("%+v: no error", r)
		}
	}
}
