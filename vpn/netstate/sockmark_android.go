//go:build linux && android

package netstate

import (
	"context"
	"fmt"
	"syscall"
)

// ProtectFunc is the type of the callback supplied by the Android host
// application (VpnService.protect via the gomobile/JNI bridge). Returns true
// on success.
type ProtectFunc func(fd int) bool

// androidMarker invokes a host-supplied callback for each libp2p socket so
// the host's VpnService.protect() can mark the socket as bypassing the TUN.
//
// The protector is set once at construction (via newAndroidMarker). To change it,
// stop the application and start a new one with a fresh marker. This avoids
// any runtime synchronisation and matches the gomobile-lib lifecycle
// (one Application instance per StartServer call).
type androidMarker struct {
	protect ProtectFunc
}

// newAndroidMarker returns a marker that calls protect for each new socket.
// Pass nil to construct a no-op marker (ControlFunc will return nil).
func newAndroidMarker(protect ProtectFunc) *androidMarker {
	return &androidMarker{protect: protect}
}

// newMarker returns a no-op Android marker. Production code should construct
// the Manager via NewAndroidManager with a protector wired to
// VpnService.protect; newMarker exists so that NewManager has a sensible
// default and callers that don't enable gateway mode don't have to
// special-case Android.
func newMarker() marker { return newAndroidMarker(nil) }

func (m *androidMarker) FWMark() uint32 { return 0 }

// Start is a no-op: socket protection is delegated to the host's
// VpnService.protect, which owns its own network tracking.
func (m *androidMarker) Start(_ context.Context) error { return nil }

func (m *androidMarker) ControlFunc() func(network, address string, c syscall.RawConn) error {
	if m.protect == nil {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			// gomobile turns Java-side exceptions into Go panics. If the
			// host VpnService has been destroyed between Application.Close
			// and a still-running libp2p dial, the JVM ref behind protect
			// may be dead; recover so the dial fails cleanly instead of
			// crashing the process.
			defer func() {
				if r := recover(); r != nil {
					logger.Warnf("VpnService.protect panicked for fd %d: %v", fd, r)
					sockErr = fmt.Errorf("VpnService.protect panic: %v", r)
				}
			}()
			if !m.protect(int(fd)) {
				sockErr = fmt.Errorf("VpnService.protect failed for fd %d", fd)
			}
		})
		if err != nil {
			return fmt.Errorf("sockmark control: %w", err)
		}
		return sockErr
	}
}
