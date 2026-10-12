// Package version holds build metadata injected via -ldflags.
package version

// Build metadata, set with -ldflags "-X .../internal/version.Version=...".
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String formats the build metadata as "version (commit, date)".
func String() string {
	return Version + " (" + Commit + ", " + Date + ")"
}
