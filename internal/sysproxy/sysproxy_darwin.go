package sysproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// proxyKinds are networksetup's names for HTTP, HTTPS and SOCKS proxies.
var proxyKinds = []string{"webproxy", "securewebproxy", "socksfirewallproxy"}

type proxyState struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	Port    int    `json:"port"`
}

type serviceState struct {
	Service string                `json:"service"`
	Proxies map[string]proxyState `json:"proxies"`
	Bypass  []string              `json:"bypass"`
}

func asUser(*exec.Cmd, Owner) error { return nil }

// services lists enabled network services.
func services(ctx context.Context) ([]string, error) {
	out, err := run(ctx, Owner{UID: -1}, "networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var svcs []string
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if (i == 0 && strings.HasPrefix(line, "An asterisk")) || line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		svcs = append(svcs, line)
	}
	if len(svcs) == 0 {
		return nil, errors.New("no enabled network services")
	}
	return svcs, nil
}

// Capture records the current proxy settings of every enabled service.
func Capture(ctx context.Context, _ Owner) (json.RawMessage, error) {
	svcs, err := services(ctx)
	if err != nil {
		return nil, err
	}
	var states []serviceState
	for _, svc := range svcs {
		st := serviceState{Service: svc, Proxies: map[string]proxyState{}}
		for _, k := range proxyKinds {
			out, err := run(ctx, Owner{UID: -1}, "networksetup", "-get"+k, svc)
			if err != nil {
				return nil, err
			}
			st.Proxies[k] = parseProxy(out)
		}
		out, err := run(ctx, Owner{UID: -1}, "networksetup", "-getproxybypassdomains", svc)
		if err != nil {
			return nil, err
		}
		st.Bypass = parseBypass(out)
		states = append(states, st)
	}
	return json.Marshal(states)
}

// Apply sets the proxy on every enabled service. Services that reject it
// (some VPN services) are skipped as long as one accepts.
func Apply(ctx context.Context, _ Owner, c Config) error {
	svcs, err := services(ctx)
	if err != nil {
		return err
	}
	port := strconv.Itoa(c.Port)
	var errs []error
	ok := 0
	for _, svc := range svcs {
		err := func() error {
			for _, k := range proxyKinds {
				if _, err := run(ctx, Owner{UID: -1}, "networksetup", "-set"+k, svc, c.Host, port); err != nil {
					return err
				}
			}
			_, err := run(ctx, Owner{UID: -1}, "networksetup", append([]string{"-setproxybypassdomains", svc}, c.Bypass...)...)
			return err
		}()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", svc, err))
			continue
		}
		ok++
	}
	if ok == 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Restore puts back what Capture recorded.
func Restore(ctx context.Context, _ Owner, saved json.RawMessage) error {
	var states []serviceState
	if err := json.Unmarshal(saved, &states); err != nil {
		return err
	}
	var errs []error
	for _, st := range states {
		for _, k := range proxyKinds {
			p := st.Proxies[k]
			if p.Server != "" {
				if _, err := run(ctx, Owner{UID: -1}, "networksetup", "-set"+k, st.Service, p.Server, strconv.Itoa(p.Port)); err != nil {
					errs = append(errs, err)
					continue
				}
			}
			state := "off"
			if p.Enabled {
				state = "on"
			}
			if _, err := run(ctx, Owner{UID: -1}, "networksetup", "-set"+k+"state", st.Service, state); err != nil {
				errs = append(errs, err)
			}
		}
		bypass := st.Bypass
		if len(bypass) == 0 {
			bypass = []string{"Empty"}
		}
		if _, err := run(ctx, Owner{UID: -1}, "networksetup", append([]string{"-setproxybypassdomains", st.Service}, bypass...)...); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func parseProxy(out string) proxyState {
	var p proxyState
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "Enabled":
			p.Enabled = v == "Yes"
		case "Server":
			p.Server = v
		case "Port":
			p.Port, _ = strconv.Atoi(v)
		}
	}
	return p
}

func parseBypass(out string) []string {
	if strings.HasPrefix(out, "There aren't any") {
		return nil
	}
	var l []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			l = append(l, line)
		}
	}
	return l
}
