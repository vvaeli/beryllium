package sysproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// Linux proxy settings are per user, and every desktop keeps them
// elsewhere. Whatever exists is set:
//   - gsettings (GNOME; also read by GTK apps and Firefox on other
//     desktops when gsettings-desktop-schemas is installed);
//   - kioslaverc (KDE);
//   - the systemd user and/or D-Bus activation environment (http_proxy & co.):
//     the only thing Chromium, Electron and CLI tools honor outside
//     GNOME/KDE, e.g. on Hyprland or sway. It affects apps started after
//     connecting (e.g. through uwsm or D-Bus), not running ones; TUN is the
//     mode that covers everything there.
// Commands run as the owner, with their session bus, when the daemon runs
// as root.

type linuxState struct {
	GNOME map[string]string `json:"gnome,omitempty"`
	KDE   map[string]string `json:"kde,omitempty"`
	// KDETool is kwriteconfig6 or kwriteconfig5.
	KDETool string `json:"kde_tool,omitempty"`
	// Env holds proxy variables of the user session; "" means unset.
	Env map[string]string `json:"env,omitempty"`
}

// envKeys are the proxy variables set in the user session environment.
var envKeys = []string{"http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}

// gnomeKeys are (schema, key) pairs saved and restored; values are
// gsettings literals.
var gnomeKeys = [][2]string{
	{"org.gnome.system.proxy", "mode"},
	{"org.gnome.system.proxy", "ignore-hosts"},
	{"org.gnome.system.proxy.http", "host"},
	{"org.gnome.system.proxy.http", "port"},
	{"org.gnome.system.proxy.https", "host"},
	{"org.gnome.system.proxy.https", "port"},
	{"org.gnome.system.proxy.socks", "host"},
	{"org.gnome.system.proxy.socks", "port"},
}

var lookPath = exec.LookPath

var kdeKeys = []string{"ProxyType", "httpProxy", "httpsProxy", "socksProxy", "NoProxyFor"}

func asUser(cmd *exec.Cmd, o Owner) error {
	if o.UID < 0 || os.Geteuid() != 0 || o.UID == 0 {
		return nil
	}
	u, err := user.LookupId(strconv.Itoa(o.UID))
	if err != nil {
		return err
	}
	gid, _ := strconv.Atoi(u.Gid)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(o.UID), Gid: uint32(gid)}}
	cmd.Env = []string{
		"HOME=" + u.HomeDir, "USER=" + u.Username, "LOGNAME=" + u.Username,
		"PATH=/usr/local/bin:/usr/bin:/bin",
	}
	for k, v := range sessionEnv(o.UID) {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	return nil
}

// sessionKeys are taken from the user's graphical session.
var sessionKeys = []string{"DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "WAYLAND_DISPLAY", "DISPLAY", "XDG_CURRENT_DESKTOP"}

// procRoot is replaced in tests.
var procRoot = "/proc"

// sessionEnv finds the session bus of uid. With systemd (or elogind plus
// dbus-broker/dbus user units) it is /run/user/<uid>/bus. Without systemd
// (e.g. Artix with runit, niri started from a TTY) the bus address is only
// known to the session's processes, so their environments are searched,
// preferring a graphical one (the compositor or its children).
func sessionEnv(uid int) map[string]string {
	env := map[string]string{}
	best := 0
	entries, _ := os.ReadDir(procRoot)
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		dir := procRoot + "/" + e.Name()
		fi, err := os.Stat(dir)
		if err != nil {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != uid {
			continue
		}
		raw, err := os.ReadFile(dir + "/environ")
		if err != nil {
			continue
		}
		cand := map[string]string{}
		for _, kv := range strings.Split(string(raw), "\x00") {
			if k, v, ok := strings.Cut(kv, "="); ok && slices.Contains(sessionKeys, k) {
				cand[k] = v
			}
		}
		score := 0
		if cand["DBUS_SESSION_BUS_ADDRESS"] != "" {
			score += 2
		}
		if cand["WAYLAND_DISPLAY"] != "" || cand["DISPLAY"] != "" {
			score++
		}
		if score > best {
			best, env = score, cand
		}
		if best == 3 {
			break
		}
	}
	runtimeDir := fmt.Sprintf("/run/user/%d", uid)
	if env["XDG_RUNTIME_DIR"] == "" {
		if _, err := os.Stat(runtimeDir); err == nil {
			env["XDG_RUNTIME_DIR"] = runtimeDir
		}
	}
	if env["DBUS_SESSION_BUS_ADDRESS"] == "" {
		if _, err := os.Stat(runtimeDir + "/bus"); err == nil {
			env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + runtimeDir + "/bus"
		}
	}
	return env
}

func hasGNOME(ctx context.Context, o Owner) bool {
	if _, err := lookPath("gsettings"); err != nil {
		return false
	}
	_, err := run(ctx, o, "gsettings", "list-keys", "org.gnome.system.proxy")
	return err == nil
}

func kdeTool() string {
	for _, t := range []string{"kwriteconfig6", "kwriteconfig5"} {
		if _, err := lookPath(t); err == nil {
			return t
		}
	}
	return ""
}

func kdeRead(t string) string { return strings.Replace(t, "write", "read", 1) }

// Capture records the owner's GNOME and/or KDE proxy settings.
func Capture(ctx context.Context, o Owner) (json.RawMessage, error) {
	var st linuxState
	if hasGNOME(ctx, o) {
		st.GNOME = map[string]string{}
		for _, k := range gnomeKeys {
			v, err := run(ctx, o, "gsettings", "get", k[0], k[1])
			if err != nil {
				return nil, err
			}
			st.GNOME[k[0]+" "+k[1]] = v
		}
	}
	if t := kdeTool(); t != "" {
		st.KDETool, st.KDE = t, map[string]string{}
		for _, k := range kdeKeys {
			v, _ := run(ctx, o, kdeRead(t), "--file", "kioslaverc", "--group", "Proxy Settings", "--key", k)
			st.KDE[k] = v
		}
	}
	if env, ok := userEnv(ctx, o); ok {
		st.Env = map[string]string{}
		for _, k := range envKeys {
			st.Env[k] = env[k]
		}
	}
	if st.GNOME == nil && st.KDE == nil && st.Env == nil {
		return nil, ErrUnsupported
	}
	return json.Marshal(st)
}

// Apply points GNOME and/or KDE at the proxy.
func Apply(ctx context.Context, o Owner, c Config) error {
	var st linuxState
	applied := false
	if hasGNOME(ctx, o) {
		host, port := quoteGVariant(c.Host), strconv.Itoa(c.Port)
		vals := map[string]string{
			"org.gnome.system.proxy mode":         "'manual'",
			"org.gnome.system.proxy ignore-hosts": gvariantList(c.Bypass),
		}
		for _, s := range []string{"http", "https", "socks"} {
			vals["org.gnome.system.proxy."+s+" host"] = host
			vals["org.gnome.system.proxy."+s+" port"] = port
		}
		st.GNOME = vals
		applied = true
	}
	if t := kdeTool(); t != "" {
		hp := fmt.Sprintf("%s %d", c.Host, c.Port)
		st.KDETool, st.KDE = t, map[string]string{
			"ProxyType":  "1",
			"httpProxy":  "http://" + hp,
			"httpsProxy": "http://" + hp,
			"socksProxy": "socks://" + hp,
			"NoProxyFor": strings.Join(c.Bypass, ","),
		}
		applied = true
	}
	if _, ok := userEnv(ctx, o); ok {
		hp := fmt.Sprintf("%s:%d", c.Host, c.Port)
		noProxy := strings.Join(c.Bypass, ",")
		st.Env = map[string]string{}
		for _, k := range envKeys {
			switch strings.ToLower(k) {
			case "all_proxy":
				st.Env[k] = "socks5://" + hp
			case "no_proxy":
				st.Env[k] = noProxy
			default:
				st.Env[k] = "http://" + hp
			}
		}
		applied = true
	}
	if !applied {
		return ErrUnsupported
	}
	return write(ctx, o, st)
}

// userEnv reads the session's proxy-relevant environment. ok is false when
// neither a systemd user manager nor dbus-update-activation-environment is
// available. Without systemd the current values come from the session's
// processes.
func userEnv(ctx context.Context, o Owner) (map[string]string, bool) {
	env := map[string]string{}
	if _, err := lookPath("systemctl"); err == nil {
		if out, err := run(ctx, o, "systemctl", "--user", "show-environment"); err == nil {
			for _, line := range strings.Split(out, "\n") {
				if k, v, ok := strings.Cut(line, "="); ok {
					env[k] = v
				}
			}
			return env, true
		}
	}
	if _, err := lookPath("dbus-update-activation-environment"); err != nil {
		return nil, false
	}
	uid := o.UID
	if uid < 0 {
		uid = os.Geteuid()
	}
	if sessionEnv(uid)["DBUS_SESSION_BUS_ADDRESS"] == "" && os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		return nil, false
	}
	for k, v := range procEnvOf(uid) {
		env[k] = v
	}
	return env, true
}

// procEnvOf returns proxy variables seen in uid's session processes.
func procEnvOf(uid int) map[string]string {
	out := map[string]string{}
	entries, _ := os.ReadDir(procRoot)
	for _, e := range entries {
		dir := procRoot + "/" + e.Name()
		fi, err := os.Stat(dir)
		if err != nil {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != uid {
			continue
		}
		raw, err := os.ReadFile(dir + "/environ")
		if err != nil || !strings.Contains(string(raw), "DBUS_SESSION_BUS_ADDRESS=") {
			continue
		}
		for _, kv := range strings.Split(string(raw), "\x00") {
			if k, v, ok := strings.Cut(kv, "="); ok && slices.Contains(envKeys, k) {
				out[k] = v
			}
		}
		return out
	}
	return out
}

// Restore writes back what Capture recorded.
func Restore(ctx context.Context, o Owner, saved json.RawMessage) error {
	var st linuxState
	if err := json.Unmarshal(saved, &st); err != nil {
		return err
	}
	return write(ctx, o, st)
}

func write(ctx context.Context, o Owner, st linuxState) error {
	var errs []error
	// mode last, so the proxy is never on with half-written settings.
	for _, k := range slices.Concat(gnomeKeys[1:], gnomeKeys[:1]) {
		v, ok := st.GNOME[k[0]+" "+k[1]]
		if !ok {
			continue
		}
		if _, err := run(ctx, o, "gsettings", "set", k[0], k[1], v); err != nil {
			errs = append(errs, err)
		}
	}
	if st.KDETool != "" {
		for _, k := range kdeKeys {
			v, ok := st.KDE[k]
			if !ok {
				continue
			}
			args := []string{"--file", "kioslaverc", "--group", "Proxy Settings", "--key", k}
			if v == "" {
				args = append(args, "--delete")
			} else {
				args = append(args, v)
			}
			if _, err := run(ctx, o, st.KDETool, args...); err != nil {
				errs = append(errs, err)
			}
		}
		// Tell running KDE apps to reload; failure only delays the change.
		_, _ = run(ctx, o, "dbus-send", "--type=signal", "/KIO/Scheduler",
			"org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:")
	}
	if st.Env != nil {
		systemd := false
		if _, err := lookPath("systemctl"); err == nil {
			_, err := run(ctx, o, "systemctl", "--user", "show-environment")
			systemd = err == nil
		}
		var set, unset []string
		for _, k := range envKeys {
			if v := st.Env[k]; v != "" {
				set = append(set, k+"="+v)
			} else {
				unset = append(unset, k)
			}
		}
		if systemd && len(set) > 0 {
			if _, err := run(ctx, o, "systemctl", append([]string{"--user", "set-environment"}, set...)...); err != nil {
				errs = append(errs, err)
			}
		}
		if systemd && len(unset) > 0 {
			if _, err := run(ctx, o, "systemctl", append([]string{"--user", "unset-environment"}, unset...)...); err != nil {
				errs = append(errs, err)
			}
		}
		// D-Bus activated apps (the only session environment without
		// systemd). It can't unset, so cleared variables are set empty,
		// which proxy-aware tools treat as no proxy.
		if _, err := lookPath("dbus-update-activation-environment"); err == nil {
			var all []string
			for _, k := range envKeys {
				all = append(all, k+"="+st.Env[k])
			}
			if _, err := run(ctx, o, "dbus-update-activation-environment", all...); err != nil && !systemd {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func quoteGVariant(s string) string {
	return "'" + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), "'", `\'`) + "'"
}

func gvariantList(l []string) string {
	q := make([]string, len(l))
	for i, s := range l {
		q[i] = quoteGVariant(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}
