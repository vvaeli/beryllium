//go:build !windows

package sysproxy

import "io"

// HelperArg is the hidden command line argument for the Windows helper.
const HelperArg = "sysproxy-helper"

// HelperMain exists only on Windows.
func HelperMain([]string, io.Reader, io.Writer) int { return 2 }

// Notify is needed only on Windows.
func Notify() {}
