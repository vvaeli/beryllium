package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

func requireAdmin() error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("this command needs an elevated (Administrator) prompt")
	}
	return nil
}

// installingUser returns the SID of the user running the elevated prompt.
func installingUser() (uid uint32, sid string, ok bool) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return 0, "", false
	}
	return 0, tu.User.Sid.String(), true
}
