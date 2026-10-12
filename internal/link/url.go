package link

import (
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// rawURL is a share link split without net/url, which rejects Hysteria2
// multi-port hosts and decodes '+' as space in base64 keys.
type rawURL struct {
	scheme   string
	user     string // decoded userinfo (may contain ':')
	hasUser  bool
	host     string // without brackets
	port     string // raw, may be a range list such as "443,1000-2000"
	path     string
	query    query
	fragment string // decoded
}

type query map[string]string

func (q query) get(keys ...string) string {
	for _, k := range keys {
		if v, ok := q[k]; ok {
			return v
		}
	}
	return ""
}

func (q query) flag(keys ...string) bool {
	switch strings.ToLower(q.get(keys...)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func splitURL(s string) (rawURL, error) {
	var u rawURL
	i := strings.Index(s, "://")
	if i <= 0 {
		return u, errors.New("not a link")
	}
	u.scheme = strings.ToLower(s[:i])
	rest := s[i+3:]
	if j := strings.IndexByte(rest, '#'); j >= 0 {
		u.fragment = unescape(rest[j+1:])
		rest = rest[:j]
	}
	if j := strings.IndexByte(rest, '?'); j >= 0 {
		u.query = parseQuery(rest[j+1:])
		rest = rest[:j]
	} else {
		u.query = query{}
	}
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		u.path = rest[j:]
		rest = rest[:j]
	}
	if j := strings.LastIndexByte(rest, '@'); j >= 0 {
		u.user = unescape(rest[:j])
		u.hasUser = true
		rest = rest[j+1:]
	}
	if strings.HasPrefix(rest, "[") {
		j := strings.IndexByte(rest, ']')
		if j < 0 {
			return u, errors.New("bad IPv6 host")
		}
		u.host = rest[1:j]
		u.port = strings.TrimPrefix(rest[j+1:], ":")
	} else if j := strings.IndexByte(rest, ':'); j >= 0 {
		u.host, u.port = rest[:j], rest[j+1:]
	} else {
		u.host = rest
	}
	return u, nil
}

func parseQuery(s string) query {
	q := query{}
	for _, kv := range strings.Split(s, "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		q[strings.ToLower(unescape(k))] = unescape(v)
	}
	return q
}

func unescape(s string) string {
	if v, err := url.PathUnescape(s); err == nil {
		return v
	}
	return s
}

// escape percent-encodes a URL component so that unescape restores it.
func escape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// encodeQuery writes non-empty values sorted by key.
func encodeQuery(q map[string]string) string {
	keys := make([]string, 0, len(q))
	for k, v := range q {
		if v != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(escape(k))
		b.WriteByte('=')
		b.WriteString(escape(q[k]))
	}
	return b.String()
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, errors.New("bad port")
	}
	return uint16(n), nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}
