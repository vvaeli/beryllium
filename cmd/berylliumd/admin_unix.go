//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"strconv"
)

func requireAdmin() error {
	if os.Geteuid() != 0 {
		return errors.New("this command needs root: run it with sudo")
	}
	return nil
}

// installingUser returns the uid of the user behind sudo.
func installingUser() (uid uint32, sid string, ok bool) {
	n, err := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	if err != nil || n == 0 {
		return 0, "", false
	}
	return uint32(n), "", true
}
