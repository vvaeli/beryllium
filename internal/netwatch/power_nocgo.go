//go:build darwin && !cgo

package netwatch

import (
	"context"
	"errors"
	"log/slog"
)

func watchPower(context.Context, *slog.Logger, func(), func()) error {
	return errors.New("built without cgo")
}
