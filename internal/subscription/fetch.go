package subscription

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ErrFetch wraps every download failure.
var ErrFetch = errors.New("subscription download failed")

// Meta is header-driven metadata from subscription panels (3x-ui, Marzban,
// Remnawave, ...).
type Meta struct {
	Title          string
	SupportURL     string
	UpdateInterval time.Duration
	Quota          *Quota
	// Routing is the raw `routing` header (base64 or ://routing/ link).
	Routing string
}

// Quota is parsed from subscription-userinfo.
type Quota struct {
	Upload   uint64    `json:"upload"`
	Download uint64    `json:"download"`
	Total    uint64    `json:"total"`
	Expire   time.Time `json:"expire"`
}

// Fetcher downloads subscriptions.
type Fetcher struct {
	Client    *http.Client
	UserAgent string
	// MaxSize caps the response body.
	MaxSize int64
	// Retries for network errors and 5xx responses.
	Retries int
	// Backoff between retries; doubled each time.
	Backoff time.Duration
}

// NewFetcher returns a fetcher with production defaults.
func NewFetcher(userAgent string) *Fetcher {
	// TODO(ROADMAP 6/7): once the tunnel exists, bind to the physical
	// interface so refreshes don't depend on the proxy being up.
	return &Fetcher{
		Client:    &http.Client{Timeout: 30 * time.Second},
		UserAgent: userAgent,
		MaxSize:   16 << 20,
		Retries:   2,
		Backoff:   time.Second,
	}
}

// Result is a fetched subscription body with its metadata.
type Result struct {
	Body []byte
	Meta Meta
}

// NormalizeURL trims whitespace and invisible characters picked up when
// copying from messengers, and validates that s is an http(s) URL with a
// host. Any port, path and query are accepted.
func NormalizeURL(s string) (string, error) {
	s = strings.TrimFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || r == '\u200b' || r == '\ufeff' || r == '"' || r == '\'' || r == '<' || r == '>'
	})
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("not a subscription URL: expected http(s)://host/path")
	}
	if u.Port() != "" {
		if p, err := strconv.Atoi(u.Port()); err != nil || p < 1 || p > 65535 {
			return "", errors.New("not a subscription URL: bad port")
		}
	}
	return s, nil
}

// Fetch downloads rawURL. Errors never contain the URL.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) (*Result, error) {
	var lastErr error
	backoff := f.Backoff
	for attempt := 0; attempt <= f.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
		res, retry, err := f.fetchOnce(ctx, rawURL)
		if err == nil {
			return res, nil
		}
		lastErr = err
		if !retry {
			break
		}
	}
	return nil, fmt.Errorf("%w: %w", ErrFetch, lastErr)
}

func (f *Fetcher) fetchOnce(ctx context.Context, rawURL string) (res *Result, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, errors.New("bad subscription URL")
	}
	req.Header.Set("User-Agent", f.UserAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := f.Client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the URL from the message
		}
		return nil, ctx.Err() == nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode >= 500, fmt.Errorf("server responded %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.MaxSize+1))
	if err != nil {
		return nil, true, err
	}
	if int64(len(body)) > f.MaxSize {
		return nil, false, fmt.Errorf("subscription is larger than %d MB", f.MaxSize>>20)
	}
	return &Result{Body: body, Meta: parseMeta(resp.Header)}, false, nil
}

func parseMeta(h http.Header) Meta {
	m := Meta{
		Title:      decodeTitle(h.Get("Profile-Title")),
		SupportURL: strings.TrimSpace(h.Get("Support-Url")),
		Routing:    strings.TrimSpace(h.Get("Routing")),
		Quota:      parseUserInfo(h.Get("Subscription-Userinfo")),
	}
	if m.Title == "" {
		if _, params, err := mime.ParseMediaType(h.Get("Content-Disposition")); err == nil {
			m.Title = strings.TrimSuffix(params["filename"], ".txt")
		}
	}
	if hours, err := strconv.ParseFloat(strings.TrimSpace(h.Get("Profile-Update-Interval")), 64); err == nil && hours > 0 {
		m.UpdateInterval = time.Duration(hours * float64(time.Hour))
	}
	return m
}

func decodeTitle(s string) string {
	s = strings.TrimSpace(s)
	if b64, ok := strings.CutPrefix(s, "base64:"); ok {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if out, err := enc.DecodeString(b64); err == nil {
				return string(out)
			}
		}
	}
	return s
}

// parseUserInfo parses "upload=1; download=2; total=3; expire=1700000000".
func parseUserInfo(s string) *Quota {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	q := &Quota{}
	found := false
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		n, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || n < 0 {
			continue
		}
		found = true
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "upload":
			q.Upload = uint64(n)
		case "download":
			q.Download = uint64(n)
		case "total":
			q.Total = uint64(n)
		case "expire":
			if n > 0 {
				q.Expire = time.Unix(int64(n), 0).UTC()
			}
		}
	}
	if !found {
		return nil
	}
	return q
}
