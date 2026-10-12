package subscription

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalizeURL(t *testing.T) {
	good := map[string]string{
		"https://sub.example.com/sub/abc":               "https://sub.example.com/sub/abc",
		"https://sub.example.com:2096/sub/abc":          "https://sub.example.com:2096/sub/abc",
		"  https://sub.example.com/sub/abc\n":           "https://sub.example.com/sub/abc",
		"\u200bhttps://sub.example.com/s?x=1&y=2\u200b": "https://sub.example.com/s?x=1&y=2",
		"http://10.0.0.1:8080/sub":                      "http://10.0.0.1:8080/sub",
		"<https://sub.example.com/sub/abc>":             "https://sub.example.com/sub/abc",
	}
	for in, want := range good {
		if got, err := NormalizeURL(in); err != nil || got != want {
			t.Errorf("NormalizeURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "sub.example.com/sub", "ftp://x/y", "https:///nohost", "https://h:99999/x", "vless://a@b:1"} {
		if _, err := NormalizeURL(bad); err == nil {
			t.Errorf("NormalizeURL(%q) succeeded", bad)
		}
	}
}

func TestFetchMetaAndBody(t *testing.T) {
	body := base64.StdEncoding.EncodeToString([]byte("trojan://pw@h.example.com:443#A\n"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != "test-agent" {
			t.Errorf("User-Agent = %q", r.UserAgent())
		}
		w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte("Мой VPN")))
		w.Header().Set("Subscription-Userinfo", "upload=10; download=20; total=1073741824; expire=1700000000")
		w.Header().Set("Profile-Update-Interval", "12")
		w.Header().Set("Support-Url", "https://t.me/support")
		w.Header().Set("Routing", "happ://routing/onadd/e30=")
		w.Write([]byte(body))
	}))
	defer srv.Close()

	f := NewFetcher("test-agent")
	res, err := f.Fetch(context.Background(), srv.URL+"/sub/token")
	if err != nil {
		t.Fatal(err)
	}
	m := res.Meta
	if m.Title != "Мой VPN" || m.SupportURL != "https://t.me/support" || m.UpdateInterval != 12*time.Hour ||
		m.Routing != "happ://routing/onadd/e30=" {
		t.Errorf("meta = %+v", m)
	}
	if q := m.Quota; q == nil || q.Upload != 10 || q.Download != 20 || q.Total != 1<<30 || q.Expire.Unix() != 1700000000 {
		t.Errorf("quota = %+v", m.Quota)
	}
	p, err := ParseBody(res.Body)
	if err != nil || len(p.Servers) != 1 {
		t.Fatalf("ParseBody = %+v, %v", p, err)
	}
}

func TestFetchRetriesServerErrors(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			http.Error(w, "busy", http.StatusBadGateway)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	f := NewFetcher("x")
	f.Backoff = time.Millisecond
	if _, err := f.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("Fetch after retries: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("calls = %d, want 3", calls.Load())
	}
}

func TestFetchErrorsHideURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	f := NewFetcher("x")
	_, err := f.Fetch(context.Background(), srv.URL+"/sub/SECRETTOKEN")
	if err == nil || strings.Contains(err.Error(), "SECRETTOKEN") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
	f.Retries = 0
	_, err = f.Fetch(context.Background(), "http://127.0.0.1:1/sub/SECRETTOKEN")
	if err == nil || strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Fatalf("network err leaks URL: %v", err)
	}
}

func TestFetchSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(make([]byte, 2<<20))
	}))
	defer srv.Close()
	f := NewFetcher("x")
	f.MaxSize = 1 << 20
	if _, err := f.Fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("oversized body accepted")
	}
}
