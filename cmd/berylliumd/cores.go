package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vvaeli/beryllium/internal/core"
)

// coreSources lists where install looks for cores to copy: next to the
// executable or in the working directory (an unpacked release archive),
// and the repo's cores/bin/<goos>-<goarch> (after just fetch-cores).
func coreSources() []string {
	var dirs []string
	if exe, err := os.Executable(); err == nil {
		if exe, err = filepath.EvalSymlinks(exe); err == nil {
			dirs = append(dirs, filepath.Join(filepath.Dir(exe), "cores"))
		}
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, filepath.Join(wd, "cores"),
			filepath.Join(wd, "cores", "bin", runtime.GOOS+"-"+runtime.GOARCH))
	}
	return dirs
}

// installCores makes sure dst has the cores before the service is
// installed. With an explicit -cores-dir the cores are used where they are;
// otherwise they are copied from the first source that has sing-box.
// Without sing-box (it always fronts the chain) the daemon can't connect,
// so install stops.
func installCores(dst string, explicit bool, sources []string, out io.Writer) error {
	if !explicit {
		for _, src := range sources {
			if same(src, dst) || !core.LoadBinaries(src).Installed(core.SingBox) {
				continue
			}
			if err := copyCores(src, dst); err != nil {
				return fmt.Errorf("copy cores to %s: %w", dst, err)
			}
			fmt.Fprintf(out, "cores copied from %s to %s\n", src, dst)
			break
		}
	}
	bins := core.LoadBinaries(dst)
	if !bins.Installed(core.SingBox) {
		hint := "run `just fetch-cores` in the repo and install from there, or pass -cores-dir <dir with sing-box, xray, mihomo>"
		if explicit {
			hint = "pass a -cores-dir that contains sing-box, xray and mihomo"
		}
		return fmt.Errorf("no sing-box in %s; %s", dst, hint)
	}
	for _, k := range core.Kinds {
		if !bins.Installed(k) {
			fmt.Fprintf(out, "warning: %s is not installed in %s; servers that need it won't work\n", k, dst)
		}
	}
	return nil
}

func same(a, b string) bool {
	ai, err1 := os.Stat(a)
	bi, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(ai, bi)
}

// copyCores copies the core executables and manifest.json. Each file goes
// through a temp file and a rename, so a running core keeps its old inode.
func copyCores(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	names := []string{"manifest.json"}
	for _, k := range core.Kinds {
		names = append(names, filepath.Base((&core.Binaries{}).Path(k)))
	}
	for _, name := range names {
		mode := os.FileMode(0o755)
		if name == "manifest.json" {
			mode = 0o644
		}
		err := copyFile(filepath.Join(src, name), filepath.Join(dst, name), mode)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}
