// Package logging configures the daemon's slog logger.
package logging

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"

	"github.com/vvaeli/beryllium/internal/redact"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Options configures Setup.
type Options struct {
	Level slog.Level
	// File is the JSON log file, rotated by size. Empty disables file logging.
	File string
	// Stderr adds human-readable output to stderr (foreground runs, journald).
	Stderr bool
}

// Setup builds a logger whose every handler masks secrets. The returned
// closer flushes and closes the log file.
func Setup(opts Options) (*slog.Logger, io.Closer) {
	hopts := &slog.HandlerOptions{Level: opts.Level, ReplaceAttr: redact.ReplaceAttr}
	var (
		handlers []slog.Handler
		closer   io.Closer = nopCloser{}
	)
	if opts.File != "" {
		lj := &lumberjack.Logger{Filename: opts.File, MaxSize: 10, MaxBackups: 3, Compress: true}
		handlers = append(handlers, slog.NewJSONHandler(lj, hopts))
		closer = lj
	}
	if opts.Stderr || len(handlers) == 0 {
		handlers = append(handlers, slog.NewTextHandler(os.Stderr, hopts))
	}
	if len(handlers) == 1 {
		return slog.New(handlers[0]), closer
	}
	return slog.New(multiHandler(handlers)), closer
}

// ParseLevel parses debug|info|warn|error.
func ParseLevel(s string) (slog.Level, error) {
	var l slog.Level
	err := l.UnmarshalText([]byte(s))
	return l, err
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

type multiHandler []slog.Handler

func (m multiHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range m {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (m multiHandler) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range m {
		if h.Enabled(ctx, r.Level) {
			errs = append(errs, h.Handle(ctx, r.Clone()))
		}
	}
	return errors.Join(errs...)
}

func (m multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make(multiHandler, len(m))
	for i, h := range m {
		out[i] = h.WithAttrs(attrs)
	}
	return out
}

func (m multiHandler) WithGroup(name string) slog.Handler {
	out := make(multiHandler, len(m))
	for i, h := range m {
		out[i] = h.WithGroup(name)
	}
	return out
}
