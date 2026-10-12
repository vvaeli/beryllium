package netwatch

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
)

// procNet is swapped in tests.
var procNet = "/proc/net"

// defaultRoutes reads the main routing table; sing-box's TUN routes live
// in their own table and never show up here.
func defaultRoutes() ([]defRoute, error) {
	var out []defRoute
	if f, err := os.Open(procNet + "/route"); err == nil {
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			// Iface Destination Gateway Flags RefCnt Use Metric Mask ...
			fs := strings.Fields(sc.Text())
			if len(fs) < 8 || fs[1] != "00000000" || fs[7] != "00000000" {
				continue
			}
			flags, _ := strconv.ParseUint(fs[3], 16, 32)
			if flags&0x1 == 0 { // RTF_UP
				continue
			}
			r := defRoute{Metric: atoi(fs[6])}
			if ifc, err := net.InterfaceByName(fs[0]); err == nil {
				r.Index = ifc.Index
			}
			if b, err := hex.DecodeString(fs[2]); err == nil && len(b) == 4 {
				// Little-endian on every Linux architecture we ship.
				var ip [4]byte
				binary.LittleEndian.PutUint32(ip[:], binary.BigEndian.Uint32(b))
				r.Gateway = netip.AddrFrom4(ip)
			}
			if r.Index != 0 {
				out = append(out, r)
			}
		}
		f.Close()
	}
	if f, err := os.Open(procNet + "/ipv6_route"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// dst dst_len src src_len gateway metric refcnt use flags iface
			fs := strings.Fields(sc.Text())
			if len(fs) < 10 || fs[0] != strings.Repeat("0", 32) || fs[1] != "00" || fs[9] == "lo" {
				continue
			}
			flags, _ := strconv.ParseUint(fs[8], 16, 32)
			if flags&0x1 == 0 || flags&0x200 != 0 { // RTF_UP, not RTF_REJECT
				continue
			}
			metric, _ := strconv.ParseUint(fs[5], 16, 32)
			r := defRoute{Metric: int(metric) + 1<<20} // prefer IPv4
			if ifc, err := net.InterfaceByName(fs[9]); err == nil {
				r.Index = ifc.Index
			}
			if b, err := hex.DecodeString(fs[4]); err == nil && len(b) == 16 {
				r.Gateway = netip.AddrFrom16([16]byte(b))
			}
			if r.Index != 0 {
				out = append(out, r)
			}
		}
		f.Close()
	}
	if len(out) == 0 {
		return nil, errNoRoute
	}
	slices.SortStableFunc(out, func(a, b defRoute) int { return a.Metric - b.Metric })
	return out, nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
