package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Process is one supervised core subprocess.
type Process struct {
	Kind Kind
	cmd  *exec.Cmd
	log  *slog.Logger

	done chan struct{}
	err  error

	mu   sync.Mutex
	tail []string // last stderr/stdout lines, for start errors
}

const tailLines = 20

// startProcess launches path with args in dir and forwards its output to
// log, tagged with the core name.
func startProcess(kind Kind, path string, args []string, dir string, log *slog.Logger) (*Process, error) {
	cmd := exec.Command(path, args...)
	cmd.Dir = dir
	setProcAttrs(cmd)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	p := &Process{Kind: kind, cmd: cmd, log: log.With("core", string(kind)), done: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		pw.Close()
		return nil, fmt.Errorf("start %s: %w", kind, err)
	}
	if err := afterStart(cmd); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		pw.Close()
		return nil, err
	}
	go p.pump(pr)
	go func() {
		p.err = cmd.Wait()
		pw.Close()
		close(p.done)
	}()
	return p, nil
}

func (p *Process) pump(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		p.mu.Lock()
		p.tail = append(p.tail, line)
		if len(p.tail) > tailLines {
			p.tail = p.tail[1:]
		}
		p.mu.Unlock()
		p.log.Info(line)
	}
	_, _ = io.Copy(io.Discard, r)
}

// PID of the running process.
func (p *Process) PID() int { return p.cmd.Process.Pid }

// Done is closed when the process exits.
func (p *Process) Done() <-chan struct{} { return p.done }

// Err is the exit error, valid after Done.
func (p *Process) Err() error { return p.err }

// Tail returns the last output lines.
func (p *Process) Tail() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.tail, "\n")
}

// Stop asks the process to exit and kills it after timeout.
func (p *Process) Stop(timeout time.Duration) {
	select {
	case <-p.done:
		return
	default:
	}
	terminate(p.cmd)
	select {
	case <-p.done:
	case <-time.After(timeout):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}

// waitListening waits until addr accepts TCP connections or the process
// exits, whichever comes first.
func (p *Process) waitListening(ctx context.Context, addr string) error {
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		select {
		case <-p.done:
			msg := lastLine(p.Tail())
			if msg == "" && p.err != nil {
				msg = p.err.Error()
			}
			return fmt.Errorf("%s exited during startup: %s", p.Kind, msg)
		case <-ctx.Done():
			return fmt.Errorf("%s did not start listening on %s: %w", p.Kind, addr, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// quietLog drops output of short-lived helper cores (latency tests).
var quietLog = slog.New(slog.DiscardHandler)

// freePort returns a currently free loopback TCP port.
func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// portFree reports whether port can be bound on loopback right now.
func portFree(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	ln.Close()
	return true
}
