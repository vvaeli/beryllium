package sysproxy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeDesktop stores gsettings and kioslaverc values.
type fakeDesktop struct {
	gnome map[string]string
	kde   map[string]string
	env   map[string]string
	calls []string
}

func (f *fakeDesktop) run(_ context.Context, _ Owner, name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "gsettings":
		switch args[0] {
		case "list-keys":
			return "mode", nil
		case "get":
			return f.gnome[args[1]+" "+args[2]], nil
		case "set":
			f.gnome[args[1]+" "+args[2]] = args[3]
		}
	case "systemctl":
		switch args[1] {
		case "show-environment":
			var lines []string
			for k, v := range f.env {
				lines = append(lines, k+"="+v)
			}
			return strings.Join(lines, "\n"), nil
		case "set-environment":
			for _, kv := range args[2:] {
				k, v, _ := strings.Cut(kv, "=")
				f.env[k] = v
			}
		case "unset-environment":
			for _, k := range args[2:] {
				delete(f.env, k)
			}
		}
	case "kreadconfig6":
		return f.kde[args[len(args)-1]], nil
	case "kwriteconfig6":
		key := args[5]
		if args[6] == "--delete" {
			delete(f.kde, key)
		} else {
			f.kde[key] = args[6]
		}
	}
	return "", nil
}

func TestLinuxCaptureApplyRestore(t *testing.T) {
	f := &fakeDesktop{gnome: map[string]string{}, kde: map[string]string{"ProxyType": "0"}, env: map[string]string{"PATH": "/usr/bin", "no_proxy": "corp"}}
	for _, k := range gnomeKeys {
		f.gnome[k[0]+" "+k[1]] = "''"
	}
	f.gnome["org.gnome.system.proxy mode"] = "'none'"
	oldRun, oldLook := run, lookPath
	run = f.run
	lookPath = func(name string) (string, error) {
		if name == "gsettings" || name == "kwriteconfig6" || name == "systemctl" {
			return "/usr/bin/" + name, nil
		}
		return "", exec.ErrNotFound
	}
	defer func() { run, lookPath = oldRun, oldLook }()
	ctx := context.Background()

	saved, err := Capture(ctx, Owner{UID: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, Owner{UID: 1000}, Config{Host: "127.0.0.1", Port: 2080, Bypass: []string{"localhost", "10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	if f.gnome["org.gnome.system.proxy mode"] != "'manual'" || f.gnome["org.gnome.system.proxy.socks port"] != "2080" ||
		f.gnome["org.gnome.system.proxy ignore-hosts"] != "['localhost', '10.0.0.0/8']" {
		t.Errorf("gnome = %v", f.gnome)
	}
	if f.kde["ProxyType"] != "1" || f.kde["socksProxy"] != "socks://127.0.0.1 2080" {
		t.Errorf("kde = %v", f.kde)
	}
	if f.env["https_proxy"] != "http://127.0.0.1:2080" || f.env["ALL_PROXY"] != "socks5://127.0.0.1:2080" || f.env["no_proxy"] != "localhost,10.0.0.0/8" {
		t.Errorf("env = %v", f.env)
	}
	// mode is written last.
	var last string
	for _, c := range f.calls {
		if strings.HasPrefix(c, "gsettings set") {
			last = c
		}
	}
	if !strings.Contains(last, " mode ") {
		t.Errorf("last gsettings call: %s", last)
	}
	if err := Restore(ctx, Owner{UID: 1000}, saved); err != nil {
		t.Fatal(err)
	}
	if f.gnome["org.gnome.system.proxy mode"] != "'none'" || f.kde["ProxyType"] != "0" || f.kde["httpProxy"] != "" {
		t.Errorf("restored gnome %v kde %v", f.gnome, f.kde)
	}
	if len(f.env) != 2 || f.env["no_proxy"] != "corp" {
		t.Errorf("restored env %v", f.env)
	}

	// Hyprland/sway: only the session environment is available.
	f2 := &fakeDesktop{env: map[string]string{}}
	run = f2.run
	lookPath = func(name string) (string, error) {
		if name == "systemctl" {
			return "/usr/bin/systemctl", nil
		}
		return "", exec.ErrNotFound
	}
	if _, err := Capture(ctx, Owner{UID: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, Owner{UID: 1000}, Config{Host: "127.0.0.1", Port: 2080}); err != nil || f2.env["http_proxy"] == "" {
		t.Errorf("env-only apply: %v %v", err, f2.env)
	}

	lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	if _, err := Capture(ctx, Owner{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("no desktop: %v", err)
	}
}

// Artix with runit and niri: no systemd, the bus address lives only in the
// session processes' environment.
func TestLinuxWithoutSystemd(t *testing.T) {
	proc := t.TempDir()
	os.MkdirAll(filepath.Join(proc, "4242"), 0o755)
	os.WriteFile(filepath.Join(proc, "4242", "environ"),
		[]byte("WAYLAND_DISPLAY=wayland-1\x00DBUS_SESSION_BUS_ADDRESS=unix:abstract=/tmp/dbus-x\x00http_proxy=http://old:1\x00"), 0o600)
	os.MkdirAll(filepath.Join(proc, "self"), 0o755) // non-numeric entries are skipped
	oldProc, oldRun, oldLook := procRoot, run, lookPath
	defer func() { procRoot, run, lookPath = oldProc, oldRun, oldLook }()
	procRoot = proc

	env := sessionEnv(os.Getuid())
	if env["DBUS_SESSION_BUS_ADDRESS"] != "unix:abstract=/tmp/dbus-x" || env["WAYLAND_DISPLAY"] != "wayland-1" {
		t.Fatalf("session env = %v", env)
	}

	var activation []string
	run = func(_ context.Context, _ Owner, name string, args ...string) (string, error) {
		if name == "dbus-update-activation-environment" {
			activation = args
		}
		return "", nil
	}
	lookPath = func(name string) (string, error) {
		if name == "dbus-update-activation-environment" {
			return "/usr/bin/" + name, nil
		}
		return "", exec.ErrNotFound
	}
	o := Owner{UID: os.Getuid()}
	saved, err := Capture(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(context.Background(), o, Config{Host: "127.0.0.1", Port: 2080}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(activation, "all_proxy=socks5://127.0.0.1:2080") {
		t.Errorf("activation env = %v", activation)
	}
	if err := Restore(context.Background(), o, saved); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(activation, "http_proxy=http://old:1") || !slices.Contains(activation, "all_proxy=") {
		t.Errorf("restored activation env = %v", activation)
	}
}
