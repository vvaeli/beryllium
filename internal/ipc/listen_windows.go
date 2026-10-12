package ipc

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// Listen creates the named pipe at addr. Access is enforced by the pipe's
// security descriptor (SYSTEM, Administrators, the daemon's own user and
// the SIDs in a), so every accepted peer is marked allowed.
func Listen(addr string, a Access) (net.Listener, error) {
	sids := append([]string{}, a.SIDs...)
	if self, err := currentUserSID(); err == nil {
		sids = append(sids, self)
	}
	var sddl strings.Builder
	sddl.WriteString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	for _, sid := range sids {
		if _, err := windows.StringToSid(sid); err != nil {
			return nil, fmt.Errorf("ipc: invalid SID %q: %w", sid, err)
		}
		fmt.Fprintf(&sddl, "(A;;GRGW;;;%s)", sid)
	}
	ln, err := winio.ListenPipe(addr, &winio.PipeConfig{SecurityDescriptor: sddl.String()})
	if err != nil {
		if pipeServed(addr) {
			return nil, ErrAlreadyRunning
		}
		return nil, err
	}
	return pipeListener{ln}, nil
}

type pipeListener struct{ net.Listener }

func (l pipeListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return peerConn{Conn: c, peer: PeerAddr{Addr: c.RemoteAddr(), Allowed: true}}, nil
}

func pipeServed(addr string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := Dial(ctx, addr)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// Dial connects to the daemon pipe.
func Dial(ctx context.Context, addr string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, addr)
}

func currentUserSID() (string, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return tu.User.Sid.String(), nil
}
