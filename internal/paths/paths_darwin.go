package paths

// Default returns the system-wide locations for a daemon run by launchd.
func Default() Paths {
	return Paths{
		StateDir: "/Library/Application Support/Beryllium",
		LogDir:   "/Library/Logs/Beryllium",
		CoresDir: "/Library/Application Support/Beryllium/cores",
		Socket:   "/var/run/beryllium.sock",
	}
}
