package netstate

import (
	"context"
	"fmt"
	"sync"
	"syscall"
)

// Manager is the single entry point to this package: it owns the socket
// marker (always-on, started once per process) and the runtime OS state of
// VPN gateway mode — the client routes and the server NAT. The struct is the
// same on every platform; the platform-specific behaviour lives in the marker
// and in the setup/teardown functions the methods call. Consumers declare
// their own narrow interfaces over the methods they use (see awl.NetManager,
// service.NetManager, service.SocketMarker).
//
// Enable/Disable methods are idempotent and safe for concurrent use. The
// internal mutex only guards the Manager's own state; the orchestration
// above (service.VPNGateway) still serialises whole enable/disable
// transactions — config, tunnel binding, DNS and the calls here — under its
// own lock.
type Manager struct {
	marker marker

	mu         sync.Mutex
	routeState *routeState
	natState   *natState
}

// NewManager returns the Manager for the current platform. On Android it
// carries a no-op socket protector — use NewAndroidManager to wire
// VpnService.protect.
func NewManager() *Manager {
	return &Manager{marker: newMarker()}
}

// Start performs the marker's initial setup and launches any background
// machinery it needs, living until ctx is cancelled. On Windows this is the
// uplink detection + network-change watcher; elsewhere it is a no-op. Must be
// called before the first libp2p socket is created (see marker.Start for the
// offline-start semantics).
func (m *Manager) Start(ctx context.Context) error {
	return m.marker.Start(ctx)
}

// ControlFunc returns a function compatible with net.Dialer.Control and the
// QUIC ListenUDP override, marking each new socket to bypass the VPN tunnel.
// It returns nil when the platform is not configured (e.g. Android before the
// host app supplies a protector).
func (m *Manager) ControlFunc() func(network, address string, c syscall.RawConn) error {
	return m.marker.ControlFunc()
}

// EnableClientRoutes installs the gateway client routes on the TUN (the
// default-route capture plus the IPv6 fail-closed fence). Idempotent: a
// second call while routes are installed is a no-op. On Windows it refuses
// while no IPv4 uplink is known (marking could not exempt libp2p traffic —
// routing loop); the condition is self-healing, so that is "try again once
// online", not a permanent failure.
func (m *Manager) EnableClientRoutes(tunIfName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.routeState != nil {
		return nil
	}
	// Markers that can be temporarily unable to guarantee loop-free marking
	// (Windows: no uplink detected right now) expose Ready. Other platforms
	// don't implement the interface and skip the check.
	if readier, ok := m.marker.(interface{ Ready() error }); ok {
		if err := readier.Ready(); err != nil {
			return fmt.Errorf("cannot enable VPN gateway: %w", err)
		}
	}

	state, err := setupGatewayRoutes(tunIfName, m.marker.FWMark())
	if err != nil {
		return fmt.Errorf("setup gateway routes: %w", err)
	}
	m.routeState = state
	return nil
}

// DisableClientRoutes removes the gateway client routes. Idempotent; a no-op
// when they are not installed. The state is dropped even if the OS teardown
// reports errors (partial leftovers are recovered by the stale-cleanup on the
// next enable), so a failure here never wedges the gateway in half-enabled.
func (m *Manager) DisableClientRoutes() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.routeState == nil {
		return nil
	}
	state := m.routeState
	m.routeState = nil
	return teardownGatewayRoutes(state)
}

// ClientRoutesActive reports whether gateway client routes are currently
// installed.
func (m *Manager) ClientRoutesActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.routeState != nil
}

// EnableServerNAT configures the exit-node data path for the awl subnet
// (Linux: ip_forward + iptables chain + MASQUERADE; Windows: WFP filter +
// per-interface forwarding + WinNAT). Idempotent: a second call while NAT is
// configured is a no-op.
func (m *Manager) EnableServerNAT(awlSubnet, tunIfName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.natState != nil {
		return nil
	}
	state, err := setupNAT(awlSubnet, tunIfName)
	if err != nil {
		return fmt.Errorf("setup NAT: %w", err)
	}
	m.natState = state
	return nil
}

// DisableServerNAT reverses EnableServerNAT. Idempotent; a no-op when NAT is
// not configured. Like DisableClientRoutes, the state is dropped even on
// teardown errors.
func (m *Manager) DisableServerNAT() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.natState == nil {
		return nil
	}
	state := m.natState
	m.natState = nil
	return teardownNAT(state)
}

// ServerNATActive reports whether the exit-node NAT is currently configured.
func (m *Manager) ServerNATActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.natState != nil
}
