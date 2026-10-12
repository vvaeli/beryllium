package sysproxy

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// fakeNetworksetup emulates networksetup's state for two services.
type fakeNetworksetup struct {
	proxies map[string]map[string]proxyState // service → kind → state
	bypass  map[string][]string
	fail    map[string]bool // services that reject changes
}

func (f *fakeNetworksetup) run(_ context.Context, _ Owner, name string, args ...string) (string, error) {
	if name != "networksetup" {
		return "", nil
	}
	cmd, rest := strings.TrimPrefix(args[0], "-"), args[1:]
	switch {
	case cmd == "listallnetworkservices":
		return "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nVPN\n*Disabled", nil
	case cmd == "getproxybypassdomains":
		if len(f.bypass[rest[0]]) == 0 {
			return "There aren't any bypass domains set on " + rest[0] + ".", nil
		}
		return strings.Join(f.bypass[rest[0]], "\n"), nil
	case strings.HasPrefix(cmd, "get"):
		p := f.proxies[rest[0]][strings.TrimPrefix(cmd, "get")]
		en := "No"
		if p.Enabled {
			en = "Yes"
		}
		return "Enabled: " + en + "\nServer: " + p.Server + "\nPort: " + itoa(p.Port) + "\nAuthenticated Proxy Enabled: 0", nil
	}
	if f.fail[rest[0]] {
		return "", errString("rejected")
	}
	switch {
	case cmd == "setproxybypassdomains":
		if len(rest) == 2 && rest[1] == "Empty" {
			f.bypass[rest[0]] = nil
		} else {
			f.bypass[rest[0]] = rest[1:]
		}
	case strings.HasSuffix(cmd, "state"):
		k := strings.TrimSuffix(strings.TrimPrefix(cmd, "set"), "state")
		p := f.proxies[rest[0]][k]
		p.Enabled = rest[1] == "on"
		f.proxies[rest[0]][k] = p
	case strings.HasPrefix(cmd, "set"):
		k := strings.TrimPrefix(cmd, "set")
		f.proxies[rest[0]][k] = proxyState{Enabled: true, Server: rest[1], Port: atoi(rest[2])}
	}
	return "", nil
}

type errString string

func (e errString) Error() string { return string(e) }

func itoa(n int) string { return strconv.Itoa(n) }

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func TestDarwinCaptureApplyRestore(t *testing.T) {
	f := &fakeNetworksetup{
		proxies: map[string]map[string]proxyState{
			"Wi-Fi": {"webproxy": {Server: "10.0.0.1", Port: 3128, Enabled: true}, "securewebproxy": {}, "socksfirewallproxy": {}},
			"VPN":   {"webproxy": {}, "securewebproxy": {}, "socksfirewallproxy": {}},
		},
		bypass: map[string][]string{"Wi-Fi": {"*.local"}},
		fail:   map[string]bool{"VPN": true},
	}
	old := run
	run = f.run
	defer func() { run = old }()
	ctx := context.Background()

	saved, err := Capture(ctx, Owner{})
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, Owner{}, Config{Host: "127.0.0.1", Port: 2080, Bypass: DefaultBypass}); err != nil {
		t.Fatal(err) // VPN rejects, Wi-Fi accepts: not an error
	}
	for _, k := range proxyKinds {
		if p := f.proxies["Wi-Fi"][k]; !p.Enabled || p.Server != "127.0.0.1" || p.Port != 2080 {
			t.Errorf("%s = %+v", k, p)
		}
	}
	if !reflect.DeepEqual(f.bypass["Wi-Fi"], DefaultBypass) {
		t.Errorf("bypass = %v", f.bypass["Wi-Fi"])
	}
	f.fail = nil
	if err := Restore(ctx, Owner{}, saved); err != nil {
		t.Fatal(err)
	}
	want := map[string]proxyState{"webproxy": {Server: "10.0.0.1", Port: 3128, Enabled: true}, "securewebproxy": {Server: "127.0.0.1", Port: 2080}, "socksfirewallproxy": {Server: "127.0.0.1", Port: 2080}}
	if !reflect.DeepEqual(f.proxies["Wi-Fi"], want) {
		t.Errorf("restored %+v", f.proxies["Wi-Fi"])
	}
	if !reflect.DeepEqual(f.bypass["Wi-Fi"], []string{"*.local"}) || f.bypass["VPN"] != nil {
		t.Errorf("bypass restored %v", f.bypass)
	}
}
