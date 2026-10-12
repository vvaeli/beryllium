package sysproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows proxy settings are per user and must be changed with WinINet
// from that user's session, so InternetSetOption also notifies running
// apps. The daemon runs as SYSTEM, so it re-runs its own executable as a
// helper (`<exe> sysproxy-helper <op>`) with the console user's token.

// HelperArg is the hidden command line argument for the helper.
const HelperArg = "sysproxy-helper"

const (
	optPerConnection   = 75 // INTERNET_OPTION_PER_CONNECTION_OPTION
	optSettingsChanged = 39
	optRefresh         = 37

	perConnFlags         = 1
	perConnProxyServer   = 2
	perConnProxyBypass   = 3
	perConnAutoConfigURL = 4

	proxyTypeDirect = 1
	proxyTypeProxy  = 2
)

var (
	wininet             = windows.NewLazySystemDLL("wininet.dll")
	procSetOption       = wininet.NewProc("InternetSetOptionW")
	procQueryOption     = wininet.NewProc("InternetQueryOptionW")
	kernel32            = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalFree      = kernel32.NewProc("GlobalFree")
	errHelperNotRunning = errors.New("no user is logged in on the console")
)

// winState mirrors the LAN connection's WinINet proxy options.
type winState struct {
	Flags   uint32 `json:"flags"`
	Server  string `json:"server"`
	Bypass  string `json:"bypass"`
	AutoURL string `json:"auto_url"`
}

// INTERNET_PER_CONN_OPTIONW: the value union is 8 bytes (FILETIME) and
// pointer-aligned on 64-bit, which uint64 reproduces on both widths.
type perConnOption struct {
	Option uint32
	Value  uint64
}

type perConnList struct {
	Size        uint32
	Connection  *uint16
	OptionCount uint32
	OptionError uint32
	Options     *perConnOption
}

// Capture records the current user's proxy settings.
func Capture(ctx context.Context, _ Owner) (json.RawMessage, error) {
	if isSystem() {
		return helper(ctx, "capture", nil)
	}
	st, err := query()
	if err != nil {
		return nil, err
	}
	return json.Marshal(st)
}

// Apply sets the proxy for the console user.
func Apply(ctx context.Context, _ Owner, c Config) error {
	bypass := append(append([]string{}, c.Bypass...), "<local>")
	st := winState{Flags: proxyTypeDirect | proxyTypeProxy, Server: fmt.Sprintf("%s:%d", c.Host, c.Port), Bypass: strings.Join(bypass, ";")}
	raw, _ := json.Marshal(st)
	if isSystem() {
		_, err := helper(ctx, "set", raw)
		return err
	}
	return set(st)
}

// Restore writes back what Capture recorded.
func Restore(ctx context.Context, _ Owner, saved json.RawMessage) error {
	if isSystem() {
		_, err := helper(ctx, "set", saved)
		return err
	}
	var st winState
	if err := json.Unmarshal(saved, &st); err != nil {
		return err
	}
	return set(st)
}

// Notify makes running apps reread the settings; frontends call it after
// the daemon changed them from another session.
func Notify() {
	_, _, _ = procSetOption.Call(0, optSettingsChanged, 0, 0)
	_, _, _ = procSetOption.Call(0, optRefresh, 0, 0)
}

// HelperMain runs a helper operation: capture prints the state as JSON,
// set reads it from stdin.
func HelperMain(args []string, stdin io.Reader, stdout io.Writer) int {
	if len(args) != 1 {
		return 2
	}
	switch args[0] {
	case "capture":
		st, err := query()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := json.NewEncoder(stdout).Encode(st); err != nil {
			return 1
		}
	case "set":
		var st winState
		if err := json.NewDecoder(stdin).Decode(&st); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := set(st); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	default:
		return 2
	}
	return 0
}

func helper(ctx context.Context, op string, input []byte) (json.RawMessage, error) {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF {
		return nil, errHelperNotRunning
	}
	var token windows.Token
	if err := windows.WTSQueryUserToken(session, &token); err != nil {
		return nil, fmt.Errorf("%w: %w", errHelperNotRunning, err)
	}
	defer token.Close()
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, HelperArg, op)
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token), HideWindow: true}
	cmd.Stdin = bytes.NewReader(input)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("system proxy helper: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return bytes.TrimSpace(out), nil
}

func isSystem() bool {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	return u.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

func query() (winState, error) {
	opts := []perConnOption{{Option: perConnFlags}, {Option: perConnProxyServer}, {Option: perConnProxyBypass}, {Option: perConnAutoConfigURL}}
	list := perConnList{OptionCount: uint32(len(opts)), Options: &opts[0]}
	list.Size = uint32(unsafe.Sizeof(list))
	size := list.Size
	r, _, err := procQueryOption.Call(0, optPerConnection, uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Pointer(&size)))
	runtime.KeepAlive(opts)
	if r == 0 {
		return winState{}, fmt.Errorf("InternetQueryOption: %w", err)
	}
	// String values are LPWSTRs allocated by WinINet.
	str := func(o *perConnOption) string {
		p := *(**uint16)(unsafe.Pointer(&o.Value))
		if p == nil {
			return ""
		}
		s := windows.UTF16PtrToString(p)
		_, _, _ = procGlobalFree.Call(uintptr(unsafe.Pointer(p)))
		return s
	}
	return winState{
		Flags:   uint32(opts[0].Value),
		Server:  str(&opts[1]),
		Bypass:  str(&opts[2]),
		AutoURL: str(&opts[3]),
	}, nil
}

func set(st winState) error {
	ptr := func(s string) *uint16 {
		if s == "" {
			return nil
		}
		p, _ := windows.UTF16PtrFromString(s)
		return p
	}
	server, bypass, auto := ptr(st.Server), ptr(st.Bypass), ptr(st.AutoURL)
	opts := []perConnOption{
		{Option: perConnFlags, Value: uint64(st.Flags)},
		{Option: perConnProxyServer},
		{Option: perConnProxyBypass},
		{Option: perConnAutoConfigURL},
	}
	// The union holds LPWSTRs; the strings stay alive via KeepAlive below.
	*(**uint16)(unsafe.Pointer(&opts[1].Value)) = server
	*(**uint16)(unsafe.Pointer(&opts[2].Value)) = bypass
	*(**uint16)(unsafe.Pointer(&opts[3].Value)) = auto
	list := perConnList{OptionCount: uint32(len(opts)), Options: &opts[0]}
	list.Size = uint32(unsafe.Sizeof(list))
	r, _, err := procSetOption.Call(0, optPerConnection, uintptr(unsafe.Pointer(&list)), uintptr(list.Size))
	runtime.KeepAlive(opts)
	runtime.KeepAlive(server)
	runtime.KeepAlive(bypass)
	runtime.KeepAlive(auto)
	if r == 0 {
		return fmt.Errorf("InternetSetOption: %w", err)
	}
	Notify()
	return nil
}
