//go:build linux && !android

package netstate

import (
	"context"
	"fmt"
	"sync"
	"syscall"
)

// awlMark is the numeric value shared by the SO_MARK fwmark applied to marked
// sockets and the policy-routing table ID holding their exemption routes.
// 0x61776C = "awl" in ASCII (lowercase). The two live in different kernel
// namespaces and don't collide; using one value makes awl-owned state
// trivially greppable in `ip rule` / `ip route show table`.
const awlMark = 0x61776C

// Manager owns the Linux OS network state behind AWL's VPN gateway feature:
// the always-on socket marking (SO_MARK, applied via ControlFunc) and the
// runtime state of gateway mode — the client routes and the server NAT.
//
// Enable/Disable methods are idempotent and safe for concurrent use. The
// internal mutex only guards the Manager's own state; the orchestration
// above (service.VPNGateway) still serialises whole enable/disable
// transactions — config, tunnel binding, DNS and the calls here — under its
// own lock.
type Manager struct {
	mu         sync.Mutex
	routeState *routeState
	natState   *natState
}

// NewManager returns the Manager for Linux. Setting SO_MARK requires
// CAP_NET_ADMIN, which AWL already needs for TUN setup, so no extra
// capability is required.
func NewManager() *Manager {
	return &Manager{}
}

// Start is a no-op on Linux: SO_MARK is interpreted by the kernel per packet,
// there is no per-socket state to keep in sync with the network.
func (m *Manager) Start(_ context.Context) error { return nil }

// ControlFunc returns a function compatible with net.Dialer.Control and the
// QUIC ListenUDP override, marking each new socket with SO_MARK so its
// traffic bypasses the VPN tunnel via the fwmark ip rule.
func (m *Manager) ControlFunc() func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var sockErr error
		err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, awlMark)
		})
		if err != nil {
			return fmt.Errorf("sockmark control: %w", err)
		}
		if sockErr != nil {
			return fmt.Errorf("sockmark SO_MARK: %w", sockErr)
		}
		return nil
	}
}

// EnableClientRoutes installs the gateway client routes on the TUN (the
// default-route capture plus the IPv6 fail-closed fence). Idempotent: a
// second call while routes are installed is a no-op.
func (m *Manager) EnableClientRoutes(tunIfName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.routeState != nil {
		return nil
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
// (ip_forward + iptables chain + MASQUERADE). Idempotent: a second call while
// NAT is configured is a no-op.
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
// teardown errors.
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
