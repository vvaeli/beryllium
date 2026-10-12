// Package subscription fetches, parses and stores subscriptions.
package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/vvaeli/beryllium/internal/link"
	"github.com/vvaeli/beryllium/internal/model"
)

// Parsed is the content of a subscription or imported config.
type Parsed struct {
	Servers []*model.Server
	// Routing holds Happ/INCY routing profile links found in the body.
	Routing []string
	// Warnings describe skipped entries. They never contain entry contents.
	Warnings []string
}

// ErrNoServers means the content parsed but contained no usable server.
var ErrNoServers = errors.New("no supported servers found")

// ParseBody detects the format (base64 or plain link list, Clash YAML,
// sing-box JSON, Xray JSON) and extracts servers.
func ParseBody(body []byte) (Parsed, error) {
	body = bytes.TrimSpace(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")))
	var (
		p   Parsed
		err error
	)
	switch {
	case len(body) == 0:
		return p, ErrNoServers
	case body[0] == '{' || body[0] == '[':
		p, err = parseJSON(body)
	case isClashYAML(body):
		p, err = parseClash(body)
	default:
		p = parseLines(decodeIfBase64(body))
	}
	if err != nil {
		return p, err
	}
	for _, s := range p.Servers {
		if s.Country == "" {
			s.Country = model.CountryFromName(s.Name)
		}
	}
	if len(p.Servers) == 0 && len(p.Routing) == 0 {
		if len(p.Warnings) > 0 {
			return p, fmt.Errorf("%w (%d entries skipped: %s)", ErrNoServers, len(p.Warnings), p.Warnings[0])
		}
		return p, ErrNoServers
	}
	return p, nil
}

// ParseConfig parses an imported file or single link. fileName helps
// recognize wg-quick configs.
func ParseConfig(content []byte, fileName, name string) (Parsed, error) {
	text := strings.TrimSpace(string(content))
	if strings.HasSuffix(strings.ToLower(fileName), ".conf") || strings.Contains(text, "[Interface]") {
		if name == "" {
			name = strings.TrimSuffix(fileName, ".conf")
		}
		srv, err := link.ParseWireGuardConf(text, name)
		if err != nil {
			return Parsed{}, err
		}
		return Parsed{Servers: []*model.Server{srv}}, nil
	}
	return ParseBody(content)
}

func decodeIfBase64(body []byte) []byte {
	if bytes.Contains(body, []byte("://")) {
		return body
	}
	compact := bytes.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, body)
	s := strings.TrimRight(string(compact), "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if out, err := enc.DecodeString(s); err == nil {
			return out
		}
	}
	return body
}

func parseLines(body []byte) Parsed {
	var p Parsed
	for i, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if link.IsRouting(line) {
			p.Routing = append(p.Routing, line)
			continue
		}
		srv, err := link.Parse(line)
		if err != nil {
			p.Warnings = append(p.Warnings, fmt.Sprintf("line %d: %v", i+1, err))
			continue
		}
		p.Servers = append(p.Servers, srv)
	}
	return p
}

func parseJSON(body []byte) (Parsed, error) {
	var probe any
	if err := json.Unmarshal(body, &probe); err != nil {
		return Parsed{}, fmt.Errorf("invalid JSON: %w", err)
	}
	switch v := probe.(type) {
	case []any:
		// Remnawave/3x-ui JSON subscriptions: an array of full Xray configs.
		var p Parsed
		for i, item := range v {
			raw, _ := json.Marshal(item)
			sub, err := parseXrayConfig(raw)
			if err != nil {
				p.Warnings = append(p.Warnings, fmt.Sprintf("config %d: %v", i+1, err))
				continue
			}
			p.Servers = append(p.Servers, sub.Servers...)
			p.Warnings = append(p.Warnings, sub.Warnings...)
		}
		return p, nil
	case map[string]any:
		if isSingBox(v) {
			return parseSingBox(body)
		}
		return parseXrayConfig(body)
	default:
		return Parsed{}, errors.New("unrecognized JSON subscription")
	}
}

func isSingBox(v map[string]any) bool {
	if _, ok := v["endpoints"]; ok {
		return true
	}
	outs, _ := v["outbounds"].([]any)
	for _, o := range outs {
		if m, ok := o.(map[string]any); ok {
			if _, ok := m["type"]; ok {
				return true
			}
			if _, ok := m["protocol"]; ok {
				return false
			}
		}
	}
	return false
}
