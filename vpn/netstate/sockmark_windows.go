//go:build windows

// Socket marking on Windows: this file holds the marking half of Manager.
//
// Manager binds libp2p (and SOCKS5 exit-node) sockets to the physical uplink
// NIC via IP_UNICAST_IF / IPV6_UNICAST_IF so their traffic bypasses the /1
// gateway routes pointing into the TUN. Always on, like SO_MARK on Linux:
// marking sockets from process start makes a later runtime gateway enable
// safe (already-open sockets are already bound to the uplink — no routing
// loop).
//
// Unlike SO_MARK (interpreted by the kernel per packet), UNICAST_IF is frozen
// into the socket, so long-lived sockets must be re-bound when the uplink
// changes. Start (manager_windows.go) launches a watcher that re-detects the
// uplink on network changes and re-applies the options across the registry of
// live UDP sockets (the eternal QUIC sockets; established TCP cannot survive
// an uplink change anyway — see sockRegistry). This is the same mechanism
// userspace WireGuard for Windows used (defaultroutemonitor +
// BindSocketToInterface4/6).
package netstate

import (
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/anywherelan/awl/vpn"
)

const (
	// IP_UNICAST_IF / IPV6_UNICAST_IF socket-option ids (not exported by
	// x/sys/windows).
	ipUnicastIF   = 31
	ipv6UnicastIF = 31
)

// ControlFunc returns a function compatible with net.Dialer.Control and the
// QUIC ListenUDP override, binding each new socket to the current uplink so
// its traffic bypasses the VPN tunnel.
func (m *Manager) ControlFunc() func(network, address string, c syscall.RawConn) error {
	// Always return a closure, even while the uplink is unknown (index 0):
	// the indexes are read on every invocation, so a late detection covers
	// every socket created afterwards, and registered UDP sockets are
	// re-bound retroactively. Returning nil here would disable marking
	// forever — libp2p captures this function exactly once in InitHost.
	return func(network, address string, c syscall.RawConn) error {
		if strings.HasPrefix(network, "udp") {
			// Long-lived socket: track it for re-binding on uplink changes.
			// TCP is not tracked — dials die with the old uplink and re-dial
			// through here; the TCP listener never passes through ControlFunc
			// (no listen hook in go-libp2p's TCP transport).
			m.registry.add(network, address, c)
		}
		ctrlErr, sockErr := m.bindSocketToUplink(network, address, c, false)
		if ctrlErr != nil {
			return fmt.Errorf("sockmark control: %w", ctrlErr)
		}
		if sockErr != nil {
			return fmt.Errorf("sockmark: %w", sockErr)
		}
		return nil
	}
}

// bindSocketToUplink sets the UNICAST_IF options on one socket, pointing it
// at the current uplink. rebind=false (socket creation) skips families whose
// index is unknown — the option simply stays
// unset. rebind=true (uplink change) always writes, because writing 0 is the
// documented way to clear a stale binding (the socket falls back to regular
// routing, which is safe: with no uplink there is no traffic at all, and once
// one appears the watcher re-binds the registry within the debounce window —
// the brief unmarked-libp2p loop into the TUN in between is the accepted
// offline-enable transient).
//
// Returns the Control-level error (dead socket — eviction signal for the
// registry) separately from setsockopt errors (live socket, wrong option —
// caller logs or fails the dial).
//
// Setsockopt errors are reported only for confident sockets: with
// confident=false both families are attempted and the wrong family's
// setsockopt is EXPECTED to fail (see unicastIFFamilies), so surfacing those
// errors would be noise on every dial and every re-bind of such a socket.
func (m *Manager) bindSocketToUplink(network, address string, c syscall.RawConn, rebind bool) (ctrlErr, sockErr error) {
	idx4 := m.index4.Load()
	idx6 := m.index6.Load()
	v4, v6, confident := unicastIFFamilies(network, address)

	var errs []error
	ctrlErr = c.Control(func(fd uintptr) {
		handle := windows.Handle(fd)
		if v6 {
			if idx6 != 0 || rebind {
				// IPV6_UNICAST_IF takes the index in host byte order.
				err := windows.SetsockoptInt(handle, windows.IPPROTO_IPV6, ipv6UnicastIF, int(idx6))
				if err != nil && confident {
					errs = append(errs, fmt.Errorf("IPV6_UNICAST_IF(%d) on %s socket: %w", idx6, network, err))
				}
			}
			// On a dual-stack socket the IPv4-mapped half routes via
			// IP_UNICAST_IF, which must be set separately.
			v6only, err := windows.GetsockoptInt(handle, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY)
			if err == nil && v6only == 0 {
				v4 = true
			}
		}
		if v4 && (idx4 != 0 || rebind) {
			// IP_UNICAST_IF takes the index in network byte order (htonl);
			// bits.ReverseBytes32 is the portable equivalent.
			err := windows.SetsockoptInt(handle, windows.IPPROTO_IP, ipUnicastIF, int(bits.ReverseBytes32(idx4)))
			if err != nil && confident {
				errs = append(errs, fmt.Errorf("IP_UNICAST_IF(%d) on %s socket: %w", idx4, network, err))
			}
		}
	})
	return ctrlErr, errors.Join(errs...)
}

// redetectUplinks recomputes both uplink indexes and, on change, re-binds
// every registered socket.
func (m *Manager) redetectUplinks() {
	idx4, idx6 := m.detectUplinkIndexes()
	old4 := m.index4.Swap(idx4)
	old6 := m.index6.Swap(idx6)
	if old4 == idx4 && old6 == idx6 {
		return
	}
	logger.Infof("uplink changed: IPv4 ifIndex %d -> %d, IPv6 ifIndex %d -> %d (re-binding %d sockets)",
		old4, idx4, old6, idx6, m.registry.size())
	m.rebindSockets()
}

// rebindSockets re-binds all registered sockets to the current indexes.
// Sockets whose fd is dead (Control fails) are evicted.
func (m *Manager) rebindSockets() {
	m.registry.forEachLive(func(e *registryEntry) error {
		ctrlErr, sockErr := m.bindSocketToUplink(e.network, e.address, e.conn, true)
		if sockErr != nil {
			logger.Warnf("re-bind %s socket %s: %v", e.network, e.address, sockErr)
		}
		return ctrlErr
	})
}

// detectUplinkIndexes scans the routing table per family for the best default
// route, excluding our own Wintun adapter (matched by its static GUID — no
// name heuristics). Index 0 means "no uplink for this family right now".
// Works before the TUN exists: LUIDFromGUID fails for an absent adapter and
// we simply exclude nothing.
func (m *Manager) detectUplinkIndexes() (idx4, idx6 uint32) {
	var exclude winipcfg.LUID
	if luid, err := winipcfg.LUIDFromGUID(vpn.WintunGUID); err == nil {
		exclude = luid
	}

	route4, ok, err := bestUplinkDefault(windows.AF_INET, exclude)
	if err != nil {
		logger.Errorf("detect IPv4 uplink: %v", err)
	} else if ok {
		idx4 = route4.IfIndex
	}
	route6, ok, err := bestUplinkDefault(windows.AF_INET6, exclude)
	if err != nil {
		logger.Errorf("detect IPv6 uplink: %v", err)
	} else if ok {
		idx6 = route6.IfIndex
	}
	return idx4, idx6
}

// unicastIFFamilies decides which address families' UNICAST_IF socket options
// apply to a socket, from the network/address pair passed to a
// net.Dialer.Control-style callback.
//
// Setting the wrong family's option fails the whole dial/listen (that was a
// real bug: IPV6_UNICAST_IF on an AF_INET socket errors out), so the decision
// must be conservative. The network string is authoritative when it carries
// the family suffix — net.Dialer resolves the address first and invokes
// Control with the concrete "tcp4"/"tcp6"/"udp4"/"udp6". For a bare
// "tcp"/"udp" we fall back to parsing the literal address. If both are
// inconclusive, confident=false tells the caller to attempt both families
// best-effort (tolerating per-family errors) instead of failing.
//
// Note: v4=true with a "6" network means "IPv6 socket" — the caller must
// still check IPV6_V6ONLY before touching the IPv4 half (dual-stack).
func unicastIFFamilies(network, address string) (v4, v6, confident bool) {
	switch {
	case strings.HasSuffix(network, "4"):
		return true, false, true
	case strings.HasSuffix(network, "6"):
		return false, true, true
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Is4() || addr.Is4In6() {
			return true, false, true
		}
		return false, true, true
	}

	return true, true, false
}
