package routing

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// SiteKind is the matcher of an Xray-style domain rule.
type SiteKind int

// Domain rule kinds.
const (
	SiteGeo     SiteKind = iota + 1 // geosite:tag[@attr]
	SiteSuffix                      // domain:example.com (and subdomains)
	SiteFull                        // full:example.com
	SiteRegex                       // regexp:...
	SiteKeyword                     // keyword:... or a bare string (substring)
)

// SiteRule is a parsed domain rule.
type SiteRule struct {
	Kind  SiteKind
	Value string
	// Tag and Attr are set for SiteGeo.
	Tag, Attr string
}

// ParseSiteRule parses Xray domain syntax as used by Happ/INCY profiles.
func ParseSiteRule(s string) (SiteRule, error) {
	s = strings.TrimSpace(s)
	prefix, rest, ok := strings.Cut(s, ":")
	if !ok {
		if s == "" {
			return SiteRule{}, errors.New("empty domain rule")
		}
		return SiteRule{Kind: SiteKeyword, Value: strings.ToLower(s)}, nil
	}
	if rest == "" {
		return SiteRule{}, fmt.Errorf("domain rule %q has no value", s)
	}
	switch strings.ToLower(prefix) {
	case "geosite":
		tag, attr, _ := strings.Cut(rest, "@")
		if tag == "" || strings.HasPrefix(tag, "!") {
			return SiteRule{}, fmt.Errorf("unsupported geosite rule %q", s)
		}
		return SiteRule{Kind: SiteGeo, Tag: strings.ToLower(tag), Attr: strings.ToLower(attr)}, nil
	case "domain":
		return SiteRule{Kind: SiteSuffix, Value: strings.ToLower(strings.TrimPrefix(rest, "."))}, nil
	case "full":
		return SiteRule{Kind: SiteFull, Value: strings.ToLower(rest)}, nil
	case "regexp":
		if _, err := regexp.Compile(rest); err != nil {
			return SiteRule{}, fmt.Errorf("domain rule %q: bad regexp", s)
		}
		return SiteRule{Kind: SiteRegex, Value: rest}, nil
	case "keyword":
		return SiteRule{Kind: SiteKeyword, Value: strings.ToLower(rest)}, nil
	case "ext", "ext-domain", "dotless":
		return SiteRule{}, fmt.Errorf("domain rule %q: %s: is not supported", s, prefix)
	}
	// Domains can't contain ':', so anything else is an unknown prefix.
	return SiteRule{}, fmt.Errorf("domain rule %q: unknown prefix %q", s, prefix)
}

// IPKind is the matcher of an Xray-style IP rule.
type IPKind int

// IP rule kinds.
const (
	IPGeo  IPKind = iota + 1 // geoip:tag, geoip:!tag
	IPCIDR                   // 1.2.3.0/24, 1.2.3.4, ::1
)

// IPRule is a parsed IP rule.
type IPRule struct {
	Kind   IPKind
	Prefix netip.Prefix
	Tag    string
	// Invert matches everything outside the geoip tag (geoip:!tag).
	Invert bool
}

// ParseIPRule parses Xray IP syntax. geoip:private needs no geo file.
func ParseIPRule(s string) (IPRule, error) {
	s = strings.TrimSpace(s)
	if rest, ok := cutPrefixFold(s, "geoip:"); ok {
		inv := strings.HasPrefix(rest, "!")
		rest = strings.TrimPrefix(rest, "!")
		if rest == "" {
			return IPRule{}, fmt.Errorf("IP rule %q has no tag", s)
		}
		return IPRule{Kind: IPGeo, Tag: strings.ToLower(rest), Invert: inv}, nil
	}
	if _, ok := cutPrefixFold(s, "ext:"); ok {
		return IPRule{}, fmt.Errorf("IP rule %q: ext: is not supported", s)
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		return IPRule{Kind: IPCIDR, Prefix: p.Masked()}, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return IPRule{Kind: IPCIDR, Prefix: netip.PrefixFrom(a, a.BitLen())}, nil
	}
	return IPRule{}, fmt.Errorf("IP rule %q: not a CIDR, IP or geoip:tag", s)
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return "", false
}
