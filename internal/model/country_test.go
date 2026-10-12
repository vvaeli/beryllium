package model

import "testing"

func TestCountryFromName(t *testing.T) {
	tests := map[string]string{
		"🇳🇱 Netherlands":  "NL",
		"Germany 🇩🇪 fast": "DE",
		"🇺🇸🇬🇧 multi":      "US",
		"no flag":         "",
		"🏳️ white flag":   "",
		"":                "",
	}
	for in, want := range tests {
		if got := CountryFromName(in); got != want {
			t.Errorf("CountryFromName(%q) = %q, want %q", in, got, want)
		}
	}
}
