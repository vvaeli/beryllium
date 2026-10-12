package netwatch

import (
	"net/netip"
	"testing"
	"time"
)

func TestJumped(t *testing.T) {
	if jumped(5*time.Second, 5*time.Second+time.Millisecond) {
		t.Fatal("a normal tick counted as sleep")
	}
	// After sleep the monotonic clock has advanced one tick, the wall
	// clock the whole night.
	if !jumped(5*time.Second, 8*time.Hour) {
		t.Fatal("wall clock jump not detected")
	}
	// NTP stepping the clock back isn't a wake.
	if jumped(5*time.Second, -time.Minute) {
		t.Fatal("backward step counted as sleep")
	}
}

func TestNetworkKey(t *testing.T) {
	if (Network{}).Key() != "" || (Network{}).Up() {
		t.Fatal("zero network is up")
	}
	a := Network{Iface: "en0", Index: 4, Gateway: netip.MustParseAddr("192.168.1.1"),
		Addrs: []netip.Addr{netip.MustParseAddr("192.168.1.10")}}
	b := a
	b.Gateway = netip.MustParseAddr("10.0.0.1")
	if a.Key() == b.Key() {
		t.Fatal("different gateways, same key")
	}
}

func TestCurrent(t *testing.T) {
	// Whatever the machine has, the TUN ranges are never reported.
	n, err := Current(nil)
	if err != nil {
		t.Skipf("no default route here: %v", err)
	}
	if !n.Up() || n.Iface == "" {
		t.Fatalf("network %+v", n)
	}
	for _, a := range n.Addrs {
		if a.IsLinkLocalUnicast() {
			t.Fatalf("link-local address in %+v", n)
		}
	}
	all := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	if len(n.Addrs) > 0 {
		if _, err := Current(all); err == nil {
			t.Fatal("excluded interface reported")
		}
	}
}
