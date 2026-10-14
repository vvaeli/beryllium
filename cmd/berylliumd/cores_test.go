package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vvaeli/beryllium/internal/core"
)

func fakeCores(t *testing.T, kinds ...core.Kind) string {
	t.Helper()
	dir := t.TempDir()
	b := &core.Binaries{Dir: dir}
	for _, k := range kinds {
		if err := os.WriteFile(b.Path(k), []byte(string(k)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"sing-box":{"version":"1.0"}}`), 0o600)
	return dir
}

func TestInstallCores(t *testing.T) {
	t.Run("copies from the first source with sing-box", func(t *testing.T) {
		onlyXray := fakeCores(t, core.Xray)
		full := fakeCores(t, core.Kinds...)
		dst := filepath.Join(t.TempDir(), "a", "cores")
		if err := installCores(dst, false, []string{"/nonexistent", onlyXray, full}, io.Discard); err != nil {
			t.Fatal(err)
		}
		bins := core.LoadBinaries(dst)
		for _, k := range core.Kinds {
			got, _ := os.ReadFile(bins.Path(k))
			if string(got) != string(k) {
				t.Fatalf("%s = %q", k, got)
			}
			// Windows has no unix permission bits.
			if fi, _ := os.Stat(bins.Path(k)); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o755 {
				t.Fatalf("%s mode %v", k, fi.Mode())
			}
		}
		if bins.Version(core.SingBox) != "1.0" {
			t.Fatal("manifest not copied")
		}
	})
	t.Run("no cores anywhere stops the install", func(t *testing.T) {
		err := installCores(t.TempDir(), false, []string{fakeCores(t, core.Xray)}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "no sing-box") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("cores already in place", func(t *testing.T) {
		dst := fakeCores(t, core.SingBox)
		var out strings.Builder
		if err := installCores(dst, false, []string{dst}, &out); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "xray is not installed") {
			t.Fatalf("no warning: %s", out.String())
		}
	})
	t.Run("explicit dir is used as is", func(t *testing.T) {
		empty := t.TempDir()
		if err := installCores(empty, true, []string{fakeCores(t, core.Kinds...)}, io.Discard); err == nil {
			t.Fatal("empty -cores-dir accepted")
		}
		if _, err := os.Stat((&core.Binaries{Dir: empty}).Path(core.SingBox)); err == nil {
			t.Fatal("copied into an explicit -cores-dir")
		}
	})
}
