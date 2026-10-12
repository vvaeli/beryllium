package netwatch

import (
	"context"
	"errors"
	"log/slog"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	login1      = "org.freedesktop.login1"
	login1Path  = "/org/freedesktop/login1"
	login1Iface = "org.freedesktop.login1.Manager"
)

// watchPower listens to PrepareForSleep from logind (systemd or elogind on
// Artix), holding a delay inhibitor so connections are closed before the
// machine sleeps (ROADMAP 7.8).
func watchPower(ctx context.Context, log *slog.Logger, sleep, wake func()) error {
	conn, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
	if err != nil {
		return err
	}
	defer conn.Close()
	var has bool
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, login1).Store(&has); err != nil {
		return err
	}
	if !has {
		return errors.New("logind is not running")
	}
	if err := conn.AddMatchSignalContext(ctx, dbus.WithMatchObjectPath(login1Path),
		dbus.WithMatchInterface(login1Iface), dbus.WithMatchMember("PrepareForSleep")); err != nil {
		return err
	}
	signals := make(chan *dbus.Signal, 8)
	conn.Signal(signals)

	obj := conn.Object(login1, login1Path)
	lock := -1
	inhibit := func() {
		var fd dbus.UnixFD
		err := obj.CallWithContext(ctx, login1Iface+".Inhibit", 0,
			"sleep", "Beryllium", "Closing tunnel connections before sleep", "delay").Store(&fd)
		if err != nil {
			log.Debug("no sleep inhibitor", "err", err)
			return
		}
		lock = int(fd)
	}
	release := func() {
		if lock >= 0 {
			unix.Close(lock)
			lock = -1
		}
	}
	defer release()
	inhibit()
	for {
		select {
		case <-ctx.Done():
			return nil
		case sig, ok := <-signals:
			if !ok {
				return errors.New("system bus closed")
			}
			if sig.Name != login1Iface+".PrepareForSleep" || len(sig.Body) != 1 {
				continue
			}
			if start, _ := sig.Body[0].(bool); start {
				runBounded(sleep)
				release()
			} else {
				inhibit()
				go wake()
			}
		}
	}
}
