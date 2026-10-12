package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// icmpPing sends one ICMP echo to host. It prefers an unprivileged ICMP
// socket (macOS; Linux with net.ipv4.ping_group_range) and falls back to a
// raw socket, which needs root/Administrator — fine for the daemon.
func icmpPing(ctx context.Context, host string, timeout time.Duration) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return 0, fmt.Errorf("resolve: %w", err)
	}
	ip := ips[0].IP
	for _, a := range ips { // prefer IPv4
		if a.IP.To4() != nil {
			ip = a.IP
			break
		}
	}
	v4 := ip.To4() != nil
	var (
		conn      *icmp.PacketConn
		dst       net.Addr
		echoType  icmp.Type = ipv4.ICMPTypeEcho
		replyType icmp.Type = ipv4.ICMPTypeEchoReply
		proto               = 1
	)
	if !v4 {
		echoType, replyType, proto = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply, 58
	}
	network, raw := "udp4", "ip4:icmp"
	if !v4 {
		network, raw = "udp6", "ip6:ipv6-icmp"
	}
	if conn, err = icmp.ListenPacket(network, ""); err == nil {
		dst = &net.UDPAddr{IP: ip}
	} else if conn, err = icmp.ListenPacket(raw, ""); err == nil {
		dst = &net.IPAddr{IP: ip}
	} else {
		return 0, fmt.Errorf("ICMP not permitted: %w", err)
	}
	defer conn.Close()

	payload := make([]byte, 16)
	_, _ = rand.Read(payload)
	seq := int(payload[0])<<8 | int(payload[1])
	msg := icmp.Message{Type: echoType, Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: seq, Data: payload}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	start := time.Now()
	if _, err := conn.WriteTo(b, dst); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return 0, errors.New("timeout")
			}
			return 0, err
		}
		reply, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil || reply.Type != replyType {
			continue
		}
		// Unprivileged sockets may rewrite the ID; match on the payload.
		if echo, ok := reply.Body.(*icmp.Echo); ok && bytes.Equal(echo.Data, payload) {
			return elapsed(start), nil
		}
	}
}
