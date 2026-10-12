package model

import "strings"

// CountryFromName extracts an ISO 3166-1 alpha-2 code from the first flag
// emoji (a pair of regional indicator symbols) in a server name.
func CountryFromName(name string) string {
	var prev rune
	for _, r := range name {
		if r >= 0x1F1E6 && r <= 0x1F1FF {
			if prev != 0 {
				return strings.ToUpper(string([]rune{'a' + (prev - 0x1F1E6), 'a' + (r - 0x1F1E6)}))
			}
			prev = r
			continue
		}
		prev = 0
	}
	return ""
}
