package paths

import (
	"path/filepath"
	"testing"
)

func TestAbs(t *testing.T) {
	p, err := Paths{StateDir: ".dev/state", LogDir: "logs", CoresDir: "cores/bin", Socket: ".dev/d.sock"}.Abs()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{p.StateDir, p.LogDir, p.CoresDir, p.Socket} {
		if !filepath.IsAbs(f) {
			t.Errorf("%q is not absolute", f)
		}
	}
	pipe := `\\.\pipe\beryllium`
	if p, _ := (Paths{Socket: pipe}).Abs(); p.Socket != pipe {
		t.Errorf("pipe name changed to %q", p.Socket)
	}
}
