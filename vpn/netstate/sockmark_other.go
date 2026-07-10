//go:build !linux && !windows

package netstate

import (
	"context"
	"syscall"
)

type noopMarker struct{}

// newMarker returns a marker that disables socket marking. application.go also
// blocks gateway mode on these platforms via setupGateway, so this should
// never be hit at runtime.
func newMarker() marker { return noopMarker{} }

func (noopMarker) FWMark() uint32 { return 0 }

func (noopMarker) Start(_ context.Context) error { return nil }

func (noopMarker) ControlFunc() func(network, address string, c syscall.RawConn) error {
	return nil
}
