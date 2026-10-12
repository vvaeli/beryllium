package client

import (
	"context"
	"errors"
	"io/fs"
	"runtime"
	"syscall"
	"time"

	"github.com/vvaeli/beryllium/internal/ipc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Error is an RPC failure translated into something the user can act on.
type Error struct {
	Msg  string
	Hint string
	Err  error
}

func (e *Error) Error() string { return e.Msg }
func (e *Error) Unwrap() error { return e.Err }

// Explain turns transport and access failures into an *Error with a hint.
// Other errors are returned with the gRPC status message only.
func (c *Client) Explain(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.PermissionDenied:
		return &Error{Msg: "access to the daemon denied", Hint: accessHint(), Err: err}
	case codes.Unavailable, codes.DeadlineExceeded:
		return c.probe(err)
	case codes.Unimplemented:
		return &Error{Msg: "the daemon does not support this yet (update berylliumd?)", Err: err}
	default:
		return errors.New(st.Message())
	}
}

// probe dials the socket directly to tell "not running" from "no access"
// from "hung", which gRPC reports uniformly as Unavailable.
func (c *Client) probe(rpcErr error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := ipc.Dial(ctx, c.addr)
	switch {
	case err == nil:
		conn.Close()
		return &Error{Msg: "the daemon is not responding", Hint: "check its logs or restart it: " + startCmd("restart"), Err: rpcErr}
	case errors.Is(err, fs.ErrPermission):
		return &Error{Msg: "access to the daemon socket denied", Hint: accessHint(), Err: err}
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ECONNREFUSED):
		return &Error{
			Msg:  "the daemon is not running (" + c.addr + ")",
			Hint: "start it: " + startCmd("start") + "\nnot installed yet? " + startCmd("install"),
			Err:  err,
		}
	default:
		return &Error{Msg: "cannot reach the daemon: " + err.Error(), Err: err}
	}
}

func startCmd(cmd string) string {
	if runtime.GOOS == "windows" {
		return "berylliumd " + cmd + " (in an Administrator prompt)"
	}
	return "sudo berylliumd " + cmd
}

func accessHint() string {
	switch runtime.GOOS {
	case "linux":
		return "add yourself to the beryllium group: sudo usermod -aG beryllium $USER, then log out and back in"
	case "windows":
		return "re-run `berylliumd install` from an Administrator prompt opened by your user"
	default:
		return "re-run `sudo berylliumd install` from your own account to grant it access"
	}
}
