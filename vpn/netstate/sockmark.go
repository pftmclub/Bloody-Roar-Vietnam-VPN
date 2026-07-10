package netstate

import (
	"context"
	"syscall"
)

// Marker abstracts the platform-specific socket-marking implementation.
type Marker interface {
	// Start performs the marker's initial setup and launches any background
	// machinery it needs, living until ctx is cancelled. On Windows this is
	// the uplink detection + network-change watcher; elsewhere it is a no-op.
	//
	// An offline start (no default route yet) is NOT an error — awl must be
	// able to start before the network is up (autostart races Wi-Fi); the
	// watcher fills the indexes in when connectivity appears. Only hard
	// failures (e.g. the OS refuses the change-notification registration)
	// return an error.
	Start(ctx context.Context) error

	// ControlFunc returns a function compatible with net.Dialer.Control and
	// the QUIC ListenUDP override. It returns nil when the platform is not
	// configured (e.g. Android before the host app supplies a protector).
	ControlFunc() func(network, address string, c syscall.RawConn) error

	// FWMark returns the firewall mark applied by this Marker on Linux. It
	// is consumed by SetupGatewayRoutes when installing the matching ip-rule.
	// Returns 0 on platforms that do not use SO_MARK.
	FWMark() uint32
}
