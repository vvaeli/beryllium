package core

import (
	"errors"
	"fmt"
	"strings"

	"github.com/vvaeli/beryllium/internal/model"
)

// Choice is the selected core and a human-readable reason.
type Choice struct {
	Kind   Kind
	Reason string
}

// ErrNoCore means no (installed) core can run the server.
var ErrNoCore = errors.New("no core can run this server")

// supports reports whether core k can run srv; a non-nil error says why not.
func supports(k Kind, srv *model.Server) error {
	switch k {
	case SingBox:
		return singBoxSupports(srv)
	case Xray:
		return xraySupports(srv)
	case Mihomo:
		return mihomoSupports(srv)
	}
	return fmt.Errorf("unknown core %q", k)
}

// Choose picks the core for srv: the override if given (it must support
// the server), otherwise the first installed core in preference order that
// supports it. installed may be nil to ignore installation.
func Choose(srv *model.Server, override Kind, installed func(Kind) bool) (Choice, error) {
	if installed == nil {
		installed = func(Kind) bool { return true }
	}
	if override != "" {
		if err := supports(override, srv); err != nil {
			return Choice{}, fmt.Errorf("%w: %s: %w", ErrNoCore, override, err)
		}
		if !installed(override) {
			return Choice{}, fmt.Errorf("%s: %w", override, ErrNotInstalled)
		}
		return Choice{Kind: override, Reason: "chosen manually"}, nil
	}
	var capable, rejected []string
	var first Kind
	for _, k := range Kinds {
		err := supports(k, srv)
		switch {
		case err != nil:
			rejected = append(rejected, fmt.Sprintf("%s: %v", k, err))
		case !installed(k):
			rejected = append(rejected, fmt.Sprintf("%s: not installed", k))
		default:
			capable = append(capable, string(k))
			if first == "" {
				first = k
			}
		}
	}
	if first == "" {
		return Choice{}, fmt.Errorf("%w (%s)", ErrNoCore, strings.Join(rejected, "; "))
	}
	reason := "preferred core"
	if len(capable) == 1 && len(rejected) > 0 {
		reason = "the only capable core (" + strings.Join(rejected, "; ") + ")"
	}
	return Choice{Kind: first, Reason: reason}, nil
}
