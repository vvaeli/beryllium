// Package version holds build metadata injected via -ldflags.
package version

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func String() string {
	return Version + " (" + Commit + ", " + Date + ")"
}
