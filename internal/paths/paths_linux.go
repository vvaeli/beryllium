package paths

// Default returns the system-wide locations for a daemon run by systemd.
func Default() Paths {
	return Paths{
		StateDir: "/var/lib/beryllium",
		LogDir:   "/var/log/beryllium",
		Socket:   "/run/beryllium/beryllium.sock",
	}
}
