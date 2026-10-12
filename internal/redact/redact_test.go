package redact

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	tests := []struct{ in, want string }{
		{"https://sub.example.com:2096/sub/abc123token", "https://sub.example.com:2096/…"},
		{"https://sub.example.com/sub/abc123token", "https://sub.example.com/…"},
		{"fetch https://sub.example.com/sub/x?flag=1 failed", "fetch https://sub.example.com/… failed"},
		{"https://sub.example.com", "https://sub.example.com"},
		{
			"vless://0b6e9f2c-1a2b-4c3d-8e9f-0123456789ab@1.2.3.4:443?security=reality&pbk=KEY#Name",
			"vless://…@1.2.3.4:443/…",
		},
		{"hy2://password@[2001:db8::1]:8443/?sni=x", "hy2://…@[2001:db8::1]:8443/…"},
		{"id=0b6e9f2c-1a2b-4c3d-8e9f-0123456789ab", "id=0b6e…"},
		{"nothing secret here", "nothing secret here"},
	}
	for _, tt := range tests {
		if got := String(tt.in); got != tt.want {
			t.Errorf("String(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestReplaceAttr(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{ReplaceAttr: ReplaceAttr}))

	const secret = "https://sub.example.com/sub/SECRETTOKEN"
	log.Info("adding "+secret, "url", secret, "err", errors.New("get "+secret+": timeout"))
	log.WithGroup("g").Info("x", "url", secret)

	out := buf.String()
	if strings.Contains(out, "SECRETTOKEN") {
		t.Fatalf("secret leaked into log output:\n%s", out)
	}
	if !strings.Contains(out, "https://sub.example.com/…") {
		t.Fatalf("masked URL missing from log output:\n%s", out)
	}
}
