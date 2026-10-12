package routing

// IDs of the builtin profiles (ROADMAP 6.16).
const (
	BuiltinProxyAll     = "builtin-all"
	BuiltinRussiaDirect = "builtin-ru-direct"
	BuiltinBlockedOnly  = "builtin-blocked"
)

// Geo data for the builtin presets. roscomvpn is small and curated for
// Russian users (the same files Happ/INCY profiles use); runetfreedom has
// the full list of domains and IPs blocked in Russia.
const (
	roscomGeoSite       = "https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geosite/release/geosite.dat"
	roscomGeoIP         = "https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geoip/release/geoip.dat"
	runetfreedomGeoSite = "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat"
	runetfreedomGeoIP   = "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat"
)

// Builtins returns the presets as profiles, so RoutingService treats them
// like any other profile.
func Builtins() []Record {
	return []Record{
		{ID: BuiltinProxyAll, Source: SourceBuiltin, Profile: Profile{
			Name: "Proxy everything", GlobalProxy: true,
		}},
		{ID: BuiltinRussiaDirect, Source: SourceBuiltin, Profile: Profile{
			Name: "Russia direct", GlobalProxy: true, DomainStrategy: "IPIfNonMatch",
			DirectSites: []string{"geosite:private", "geosite:category-ru", "geosite:whitelist",
				"domain:ru", "domain:su", "domain:xn--p1ai"},
			DirectIP:   []string{"geoip:private", "geoip:direct"},
			GeoSiteURL: roscomGeoSite, GeoIPURL: roscomGeoIP,
		}},
		{ID: BuiltinBlockedOnly, Source: SourceBuiltin, Profile: Profile{
			Name: "Only blocked in Russia", GlobalProxy: false, DomainStrategy: "IPIfNonMatch",
			ProxySites: []string{"geosite:ru-blocked"},
			ProxyIP:    []string{"geoip:ru-blocked"},
			GeoSiteURL: runetfreedomGeoSite, GeoIPURL: runetfreedomGeoIP,
		}},
	}
}
