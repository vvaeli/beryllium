package routing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GeoTimeout bounds one geo file download, as in INCY.
const GeoTimeout = 3 * time.Minute

// maxGeoSize guards against a misconfigured URL streaming forever.
const maxGeoSize = 256 << 20

// GeoCache downloads geoip.dat/geosite.dat files into Dir. Downloads never
// go through the tunnel: the client has no proxy, and in TUN mode the
// daemon's own traffic is routed direct.
type GeoCache struct {
	Dir    string
	Client *http.Client
}

type geoMeta struct {
	URL       string    `json:"url"`
	SHA256    string    `json:"sha256"`
	FetchedAt time.Time `json:"fetched_at"`
}

// Path is where the file for rawURL is cached.
func (c *GeoCache) Path(rawURL string) string {
	h := sha256.Sum256([]byte(rawURL))
	return filepath.Join(c.Dir, hex.EncodeToString(h[:8])+".dat")
}

// Cached reports whether rawURL is already downloaded.
func (c *GeoCache) Cached(rawURL string) bool {
	_, err := os.Stat(c.Path(rawURL))
	return err == nil
}

// Ensure makes sure the file for rawURL is cached and current, following
// INCY: if <url>.sha256 is published and matches the cached file, nothing is
// downloaded (even when forced). Without it, the file is downloaded when
// missing, when forced, or when the profile's LastUpdated is newer than the
// cached copy. It reports whether the file changed.
func (c *GeoCache) Ensure(ctx context.Context, rawURL string, lastUpdated time.Time, force bool) (bool, error) {
	if err := checkGeoURL(rawURL); err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, GeoTimeout)
	defer cancel()
	path := c.Path(rawURL)
	meta := c.meta(path)
	_, statErr := os.Stat(path)
	have := statErr == nil && meta.URL == rawURL

	want := c.remoteSum(ctx, rawURL)
	switch {
	case have && want != "" && want == meta.SHA256:
		return false, nil
	case have && want == "" && !force && !lastUpdated.After(meta.FetchedAt):
		return false, nil
	}

	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return false, err
	}
	sum, err := c.download(ctx, rawURL, path+".tmp")
	if err != nil {
		os.Remove(path + ".tmp")
		return false, err
	}
	if want != "" && sum != want {
		os.Remove(path + ".tmp")
		return false, fmt.Errorf("geo file %s: SHA-256 mismatch", host(rawURL))
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return false, err
	}
	m := geoMeta{URL: rawURL, SHA256: sum, FetchedAt: time.Now().UTC()}
	raw, _ := json.Marshal(m)
	_ = os.WriteFile(path+".json", raw, 0o600)
	return meta.SHA256 != sum, nil
}

func (c *GeoCache) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: true}}
}

func (c *GeoCache) meta(path string) geoMeta {
	var m geoMeta
	if raw, err := os.ReadFile(path + ".json"); err == nil {
		_ = json.Unmarshal(raw, &m)
	}
	return m
}

// remoteSum fetches <url>.sha256 (or .sha256sum); "" when not published.
func (c *GeoCache) remoteSum(ctx context.Context, rawURL string) string {
	for _, suffix := range []string{".sha256", ".sha256sum"} {
		body, err := c.get(ctx, rawURL+suffix, 1024)
		if err != nil {
			continue
		}
		if f := strings.Fields(string(body)); len(f) > 0 && len(f[0]) == 64 {
			if _, err := hex.DecodeString(f[0]); err == nil {
				return strings.ToLower(f[0])
			}
		}
	}
	return ""
}

func (c *GeoCache) get(ctx context.Context, rawURL string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

func (c *GeoCache) download(ctx context.Context, rawURL, dst string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return "", fmt.Errorf("download geo file from %s: %w", host(rawURL), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download geo file from %s: HTTP %d", host(rawURL), resp.StatusCode)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxGeoSize+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fmt.Errorf("download geo file from %s: %w", host(rawURL), err)
	}
	if n > maxGeoSize {
		return "", fmt.Errorf("geo file from %s is larger than %d MB", host(rawURL), maxGeoSize>>20)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func checkGeoURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errors.New("geo file URL must be http(s)://")
	}
	return nil
}

// host is safe to show in errors; geo URLs are public but may carry tokens.
func host(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Host
	}
	return "?"
}
