//go:build !linux

package main

// initSystem is only needed for Linux init systems kardianos/service
// doesn't cover.
type initSystem interface {
	name() string
	install(exe string, args []string) error
	uninstall() error
	control(cmd string) error
}

func nativeInit() initSystem { return nil }
