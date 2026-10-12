// Package redact masks secrets (subscription URLs, share links, UUIDs)
// before text leaves the daemon through logs or diagnostics.
package redact

import (
	"fmt"
	"log/slog"
	"regexp"
)

var (
	// scheme://[userinfo@]host[:port][rest]
	urlRe = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*)://([^\s/?#@]*@)?(\[[0-9a-f:.]+\]|[^\s/?#:@]+)(:\d+)?([/?#][^\s]*)?`)
	// Canonical UUIDs (VLESS/VMess ids, subscription tokens).
	uuidRe = regexp.MustCompile(`(?i)\b([0-9a-f]{4})[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
)

// String masks secrets in s. URLs keep only scheme, host and port:
// "https://host:2096/sub/token" → "https://host:2096/…",
// "vless://uuid@host:443?…#name" → "vless://…@host:443/…".
func String(s string) string {
	s = urlRe.ReplaceAllStringFunc(s, func(m string) string {
		g := urlRe.FindStringSubmatch(m)
		out := g[1] + "://"
		if g[2] != "" {
			out += "…@"
		}
		out += g[3] + g[4]
		if g[5] != "" {
			out += "/…"
		}
		return out
	})
	return uuidRe.ReplaceAllString(s, "$1…")
}

// ReplaceAttr is a slog.HandlerOptions.ReplaceAttr that masks secrets in the
// message and in string, error and Stringer attribute values.
func ReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(String(a.Value.String()))
	case slog.KindAny:
		switch v := a.Value.Any().(type) {
		case error:
			a.Value = slog.StringValue(String(v.Error()))
		case fmt.Stringer:
			a.Value = slog.StringValue(String(v.String()))
		}
	}
	return a
}
