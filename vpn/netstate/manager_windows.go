//go:build windows

package netstate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Manager owns the Windows OS network state behind AWL's VPN gateway feature:
// the always-on socket marking (IP_UNICAST_IF binding to the physical uplink
// NIC — mechanism and lifecycle in sockmark_windows.go) and the runtime state
// of gateway mode — the client routes and the server NAT.
//
// Enable/Disable methods are idempotent and safe for concurrent use. The
// internal mutex only guards the Manager's own state; the orchestration
// above (service.VPNGateway) still serialises whole enable/disable
// transactions — config, tunnel binding, DNS and the calls here — under its
// own lock.
type Manager struct {
	// index4/index6 are the current uplink interface indexes per address
	// family (0 = unknown right now), tracked separately because on
	// multihomed hosts the IPv6 default route may live on a different NIC
	// than the IPv4 one. Atomics, not m.mu: ControlFunc reads them on every
	// dial — a hot path that must not contend with enable/disable
	// transactions.
	index4 atomic.Uint32
	index6 atomic.Uint32

	// registry tracks the live long-lived UDP sockets for re-binding on
	// uplink changes; kickCh feeds debounced network-change notifications to
	// the watch goroutine. Both belong to the marking machinery in
	// sockmark_windows.go.
	registry sockRegistry
	kickCh   chan struct{}

	mu         sync.Mutex
	routeState *routeState
	natState   *natState
}

// NewManager returns the Manager for Windows. The uplink indexes stay zero
// (marking is a no-op) until Start performs the initial detection.
func NewManager() *Manager {
	return &Manager{kickCh: make(chan struct{}, 1)}
}

// Start synchronously detects the current uplink and launches the
// network-change watcher, which lives until ctx is cancelled. An offline
// start (no default route → both indexes 0) is not an error: the watcher
// picks the uplink up when connectivity appears and re-binds registered
// sockets, so a restart is never needed. Only the change-notification
// registration itself can fail — and that deliberately fails Init (unlike
// the Linux Start, whose netlink monitor is best-effort staleness tracking):
// the notifications drive socket marking itself, which never recovers
// without them. Must be called before the first libp2p socket is created.
func (m *Manager) Start(ctx context.Context) error {
	m.redetect()

	routeCb, err := winipcfg.RegisterRouteChangeCallback(func(_ winipcfg.MibNotificationType, route *winipcfg.MibIPforwardRow2) {
		// Only default-route changes can change the uplink choice.
		if route != nil && route.DestinationPrefix.PrefixLength == 0 {
			m.kick()
		}
	})
	if err != nil {
		return fmt.Errorf("register route change callback: %w", err)
	}
	ifaceCb, err := winipcfg.RegisterInterfaceChangeCallback(func(notificationType winipcfg.MibNotificationType, _ *winipcfg.MibIPInterfaceRow) {
		// Parameter changes cover interface metric flips, which reorder
		// default routes without touching the route table itself.
		if notificationType == winipcfg.MibParameterNotification {
			m.kick()
		}
	})
	if err != nil {
		_ = routeCb.Unregister()
		return fmt.Errorf("register interface change callback: %w", err)
	}

	go m.watch(ctx, func() {
		_ = routeCb.Unregister()
		_ = ifaceCb.Unregister()
	})

	logger.Infof("socket marker started (IPv4 uplink ifIndex %d, IPv6 uplink ifIndex %d)",
		m.index4.Load(), m.index6.Load())
	return nil
}

// EnableClientRoutes installs the gateway client routes on the TUN (the
// default-route capture plus the IPv6 fail-closed fence). Idempotent: a
// second call while routes are installed is a no-op. It refuses while no
// IPv4 uplink is known (marking could not exempt libp2p traffic — routing
// loop); the condition is self-healing (the watcher re-binds sockets when
// connectivity appears), so that is "try again once online", not a permanent
// failure. IPv6 is not required: the tunnel is IPv4-only and gateway mode
// fences IPv6.
func (m *Manager) EnableClientRoutes(tunIfName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.routeState != nil {
		return nil
	}
	// TODO(gateway-offline-start): soften this gate to a warning so gateway
	// client mode can be enabled/booted offline and self-heal when connectivity appears
	if m.index4.Load() == 0 {
		return errors.New("cannot enable VPN gateway: no active network connection (no IPv4 default route)")
	}

	state, err := m.setupGatewayRoutes(tunIfName)
	if err != nil {
		return fmt.Errorf("setup gateway routes: %w", err)
	}
	m.routeState = state
	return nil
}

// DisableClientRoutes removes the gateway client routes. Idempotent; a no-op
// when they are not installed. The state is dropped even if the OS teardown
// reports errors (partial leftovers die with the TUN adapter anyway), so a
// failure here never wedges the gateway in half-enabled.
func (m *Manager) DisableClientRoutes() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.routeState == nil {
		return nil
	}
	state := m.routeState
	m.routeState = nil
	return m.teardownGatewayRoutes(state)
}

// ClientRoutesActive reports whether gateway client routes are currently
// installed.
func (m *Manager) ClientRoutesActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.routeState != nil
}

// EnableServerNAT configures the exit-node data path for the awl subnet
// (WFP filter + per-interface forwarding + WinNAT). Idempotent: a second
// call while NAT is configured is a no-op.
func (m *Manager) EnableServerNAT(awlSubnet, tunIfName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.natState != nil {
		return nil
	}
	state, err := m.setupNAT(awlSubnet, tunIfName)
	if err != nil {
		return fmt.Errorf("setup NAT: %w", err)
	}
	m.natState = state
	return nil
}

// DisableServerNAT reverses EnableServerNAT. Idempotent; a no-op when NAT is
// not configured. Like DisableClientRoutes, the state is dropped even on
// teardown errors (partial leftovers are recovered by the stale-cleanup on
// the next enable).
func (m *Manager) DisableServerNAT() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.natState == nil {
		return nil
	}
	state := m.natState
	m.natState = nil
	return m.teardownNAT(state)
}

// ServerNATActive reports whether the exit-node NAT is currently configured.
func (m *Manager) ServerNATActive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.natState != nil
}
