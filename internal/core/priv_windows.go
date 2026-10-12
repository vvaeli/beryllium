package core

import "golang.org/x/sys/windows"

// privileged reports whether the process may create TUN interfaces.
func privileged() bool { return windows.GetCurrentProcessToken().IsElevated() }
