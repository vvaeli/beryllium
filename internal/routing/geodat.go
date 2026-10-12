package routing

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

// Domain match types in v2ray geosite.dat (routercommon.Domain.Type).
const (
	domainPlain  = 0 // substring
	domainRegex  = 1
	domainSuffix = 2 // "RootDomain": the domain and its subdomains
	domainFull   = 3
)

// SiteEntry is one domain of a geosite tag.
type SiteEntry struct {
	Type  int
	Value string
	Attrs []string
}

// IPList is one geoip tag.
type IPList struct {
	CIDRs   []netip.Prefix
	Reverse bool
}

// ReadGeoSite extracts the given tags (case-insensitive) from a v2ray
// geosite.dat (GeoSiteList protobuf). Tags missing from the file are absent
// from the result.
func ReadGeoSite(data []byte, tags []string) (map[string][]SiteEntry, error) {
	want := tagSet(tags)
	out := map[string][]SiteEntry{}
	err := eachEntry(data, func(entry []byte) error {
		code, err := countryCode(entry)
		if err != nil {
			return err
		}
		if !want[code] {
			return nil
		}
		var domains []SiteEntry
		err = fields(entry, func(num protowire.Number, typ protowire.Type, v []byte, _ uint64) error {
			if num != 2 || typ != protowire.BytesType {
				return nil
			}
			d, err := parseDomain(v)
			if err != nil {
				return err
			}
			domains = append(domains, d)
			return nil
		})
		if err != nil {
			return err
		}
		out[code] = append(out[code], domains...)
		return nil
	})
	return out, err
}

// ReadGeoIP extracts the given tags (case-insensitive) from a v2ray
// geoip.dat (GeoIPList protobuf).
func ReadGeoIP(data []byte, tags []string) (map[string]IPList, error) {
	want := tagSet(tags)
	out := map[string]IPList{}
	err := eachEntry(data, func(entry []byte) error {
		code, err := countryCode(entry)
		if err != nil {
			return err
		}
		if !want[code] {
			return nil
		}
		l := out[code]
		err = fields(entry, func(num protowire.Number, typ protowire.Type, v []byte, n uint64) error {
			switch {
			case num == 2 && typ == protowire.BytesType:
				p, err := parseCIDR(v)
				if err != nil {
					return err
				}
				l.CIDRs = append(l.CIDRs, p)
			case num == 3 && typ == protowire.VarintType:
				l.Reverse = n != 0
			}
			return nil
		})
		if err != nil {
			return err
		}
		out[code] = l
		return nil
	})
	return out, err
}

// ListTags returns every tag in a geosite.dat or geoip.dat.
func ListTags(data []byte) ([]string, error) {
	var tags []string
	err := eachEntry(data, func(entry []byte) error {
		code, err := countryCode(entry)
		if err == nil {
			tags = append(tags, code)
		}
		return err
	})
	return tags, err
}

func tagSet(tags []string) map[string]bool {
	m := map[string]bool{}
	for _, t := range tags {
		m[strings.ToLower(t)] = true
	}
	return m
}

var errMalformed = errors.New("malformed geo data file")

// eachEntry calls fn for every field-1 message of a *List.
func eachEntry(data []byte, fn func([]byte) error) error {
	return fields(data, func(num protowire.Number, typ protowire.Type, v []byte, _ uint64) error {
		if num == 1 && typ == protowire.BytesType {
			return fn(v)
		}
		return nil
	})
}

// fields walks a protobuf message. For bytes fields v is set, for varints n.
func fields(b []byte, fn func(num protowire.Number, typ protowire.Type, v []byte, n uint64) error) error {
	for len(b) > 0 {
		num, typ, l := protowire.ConsumeTag(b)
		if l < 0 {
			return errMalformed
		}
		b = b[l:]
		var (
			v []byte
			n uint64
		)
		switch typ {
		case protowire.BytesType:
			v, l = protowire.ConsumeBytes(b)
		case protowire.VarintType:
			n, l = protowire.ConsumeVarint(b)
		default:
			l = protowire.ConsumeFieldValue(num, typ, b)
		}
		if l < 0 {
			return errMalformed
		}
		b = b[l:]
		if err := fn(num, typ, v, n); err != nil {
			return err
		}
	}
	return nil
}

func countryCode(entry []byte) (string, error) {
	var code string
	err := fields(entry, func(num protowire.Number, typ protowire.Type, v []byte, _ uint64) error {
		if num == 1 && typ == protowire.BytesType {
			code = strings.ToLower(string(v))
		}
		return nil
	})
	return code, err
}

func parseDomain(b []byte) (SiteEntry, error) {
	var d SiteEntry
	err := fields(b, func(num protowire.Number, typ protowire.Type, v []byte, n uint64) error {
		switch {
		case num == 1 && typ == protowire.VarintType:
			d.Type = int(n)
		case num == 2 && typ == protowire.BytesType:
			d.Value = string(v)
		case num == 3 && typ == protowire.BytesType:
			return fields(v, func(num protowire.Number, typ protowire.Type, v []byte, _ uint64) error {
				if num == 1 && typ == protowire.BytesType {
					d.Attrs = append(d.Attrs, strings.ToLower(string(v)))
				}
				return nil
			})
		}
		return nil
	})
	return d, err
}

func parseCIDR(b []byte) (netip.Prefix, error) {
	var (
		ip     []byte
		prefix uint64
	)
	err := fields(b, func(num protowire.Number, typ protowire.Type, v []byte, n uint64) error {
		switch {
		case num == 1 && typ == protowire.BytesType:
			ip = v
		case num == 2 && typ == protowire.VarintType:
			prefix = n
		}
		return nil
	})
	if err != nil {
		return netip.Prefix{}, err
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || int(prefix) > addr.BitLen() {
		return netip.Prefix{}, fmt.Errorf("%w: bad CIDR", errMalformed)
	}
	return netip.PrefixFrom(addr, int(prefix)).Masked(), nil
}
