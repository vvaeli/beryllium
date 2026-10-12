// Command fetchcores downloads the pinned proxy cores listed in
// cores/versions.json, verifies their SHA-256 and unpacks the binaries into
// cores/bin/<goos>-<goarch>/. With -bump it rewrites versions.json from the
// latest GitHub releases (digests come from the GitHub API).
//
//	go -C tools run ./fetchcores                 # current platform
//	go -C tools run ./fetchcores -platform all   # every platform
//	go -C tools run ./fetchcores -bump
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Versions is the schema of cores/versions.json.
type Versions struct {
	Cores map[string]Core `json:"cores"`
}

// Core is one pinned core release.
type Core struct {
	Repo    string           `json:"repo"`
	Version string           `json:"version"`
	Assets  map[string]Asset `json:"assets"` // key: goos-goarch
}

// Asset is a release archive for one platform.
type Asset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

// Manifest records unpacked binaries and their hashes for the daemon.
type Manifest map[string]struct {
	Version string `json:"version"`
	File    string `json:"file"`
	SHA256  string `json:"sha256"`
}

var platforms = []string{"linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64", "windows-amd64", "windows-arm64"}

func main() {
	root := flag.String("root", "..", "repository root (relative to tools/)")
	platform := flag.String("platform", runtime.GOOS+"-"+runtime.GOARCH, "goos-goarch or \"all\"")
	bump := flag.Bool("bump", false, "update versions.json to the latest releases")
	flag.Parse()

	vpath := filepath.Join(*root, "cores", "versions.json")
	var err error
	if *bump {
		err = bumpVersions(vpath)
	} else {
		err = fetch(vpath, filepath.Join(*root, "cores", "bin"), *platform)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fetchcores:", err)
		os.Exit(1)
	}
}

func fetch(vpath, outRoot, platform string) error {
	raw, err := os.ReadFile(vpath)
	if err != nil {
		return err
	}
	var v Versions
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	plats := []string{platform}
	if platform == "all" {
		plats = platforms
	}
	for _, plat := range plats {
		dir := filepath.Join(outRoot, plat)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		old := Manifest{}
		if raw, err := os.ReadFile(filepath.Join(dir, "manifest.json")); err == nil {
			_ = json.Unmarshal(raw, &old)
		}
		man := Manifest{}
		for _, name := range sortedKeys(v.Cores) {
			c := v.Cores[name]
			a, ok := c.Assets[plat]
			if !ok {
				return fmt.Errorf("%s has no asset for %s", name, plat)
			}
			if e, ok := old[name]; ok && e.Version == c.Version && fileHash(filepath.Join(dir, e.File)) == e.SHA256 {
				man[name] = e
				fmt.Printf("%s %s %s: up to date\n", name, c.Version, plat)
				continue
			}
			fmt.Printf("%s %s %s ... ", name, c.Version, plat)
			data, err := download(a.URL)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if got := sha256Hex(data); got != a.SHA256 {
				return fmt.Errorf("%s: checksum mismatch: got %s, want %s", name, got, a.SHA256)
			}
			bin, err := extract(data, a.URL, name)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			file := name
			if strings.HasPrefix(plat, "windows-") {
				file += ".exe"
			}
			if err := os.WriteFile(filepath.Join(dir, file), bin, 0o755); err != nil {
				return err
			}
			e := man[name]
			e.Version, e.File, e.SHA256 = c.Version, file, sha256Hex(bin)
			man[name] = e
			fmt.Println("ok")
		}
		out, _ := json.MarshalIndent(man, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(out, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func download(url string) ([]byte, error) {
	c := &http.Client{Timeout: 5 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 200<<20))
}

// extract returns the core binary from a .tar.gz, .zip or .gz archive.
func extract(data []byte, url, name string) ([]byte, error) {
	match := func(p string) bool {
		base := strings.TrimSuffix(path.Base(p), ".exe")
		return base == name || (name == "mihomo" && strings.HasPrefix(base, "mihomo"))
	}
	switch {
	case strings.HasSuffix(url, ".tar.gz"):
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if err != nil {
				return nil, fmt.Errorf("binary not found in archive: %w", err)
			}
			if h.Typeflag == tar.TypeReg && match(h.Name) {
				return io.ReadAll(tr)
			}
		}
	case strings.HasSuffix(url, ".zip"):
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if !f.FileInfo().IsDir() && match(f.Name) {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(rc)
			}
		}
		return nil, errors.New("binary not found in archive")
	case strings.HasSuffix(url, ".gz"):
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		return io.ReadAll(gz)
	}
	return nil, fmt.Errorf("unknown archive type: %s", url)
}

// assetName returns the release asset name for a core, version and platform.
func assetName(name, version, plat string) string {
	goos, arch, _ := strings.Cut(plat, "-")
	switch name {
	case "sing-box":
		ext := ".tar.gz"
		if goos == "windows" {
			ext = ".zip"
		}
		return fmt.Sprintf("sing-box-%s-%s-%s%s", version, goos, arch, ext)
	case "xray":
		xos := map[string]string{"linux": "linux", "darwin": "macos", "windows": "windows"}[goos]
		xarch := map[string]string{"amd64": "64", "arm64": "arm64-v8a"}[arch]
		return fmt.Sprintf("Xray-%s-%s.zip", xos, xarch)
	case "mihomo":
		ext := ".gz"
		if goos == "windows" {
			ext = ".zip"
		}
		return fmt.Sprintf("mihomo-%s-%s-v%s%s", goos, arch, version, ext)
	}
	return ""
}

func bumpVersions(vpath string) error {
	repos := map[string]string{"sing-box": "SagerNet/sing-box", "xray": "XTLS/Xray-core", "mihomo": "MetaCubeX/mihomo"}
	v := Versions{Cores: map[string]Core{}}
	for _, name := range sortedKeys(repos) {
		var rel struct {
			Tag    string `json:"tag_name"`
			Assets []struct {
				Name   string `json:"name"`
				URL    string `json:"browser_download_url"`
				Digest string `json:"digest"`
			} `json:"assets"`
		}
		raw, err := download("https://api.github.com/repos/" + repos[name] + "/releases/latest")
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &rel); err != nil {
			return err
		}
		c := Core{Repo: repos[name], Version: strings.TrimPrefix(rel.Tag, "v"), Assets: map[string]Asset{}}
		for _, plat := range platforms {
			want := assetName(name, c.Version, plat)
			for _, a := range rel.Assets {
				if a.Name == want {
					sum, ok := strings.CutPrefix(a.Digest, "sha256:")
					if !ok {
						return fmt.Errorf("%s: no sha256 digest for %s", name, a.Name)
					}
					c.Assets[plat] = Asset{URL: a.URL, SHA256: sum}
				}
			}
			if _, ok := c.Assets[plat]; !ok {
				return fmt.Errorf("%s %s: asset %s not found", name, c.Version, want)
			}
		}
		v.Cores[name] = c
		fmt.Println(name, c.Version)
	}
	out, _ := json.MarshalIndent(v, "", "  ")
	return os.WriteFile(vpath, append(out, '\n'), 0o644)
}

func fileHash(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return sha256Hex(b)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
