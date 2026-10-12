package netwatch

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultRoutesLinux(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no lo")
	}
	dir := t.TempDir()
	saved := procNet
	procNet = dir
	t.Cleanup(func() { procNet = saved })
	// lo stands in for a physical interface (the test needs a real index).
	route := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"lo\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n" +
		"lo\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n" +
		"lo\t00000000\t0201A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
	os.WriteFile(filepath.Join(dir, "route"), []byte(route), 0o600)
	rs, err := defaultRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 || rs[0].Index != lo.Index || rs[0].Gateway.String() != "192.168.1.2" || rs[1].Gateway.String() != "192.168.1.1" {
		t.Fatalf("routes %+v", rs)
	}
	os.WriteFile(filepath.Join(dir, "route"), []byte("Iface\tDestination\n"), 0o600)
	if _, err := defaultRoutes(); err == nil {
		t.Fatal("no default route, no error")
	}
}
