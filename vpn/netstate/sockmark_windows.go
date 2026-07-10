//go:build windows

package netstate

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/anywherelan/awl/vpn"
)

const (
	// IP_UNICAST_IF / IPV6_UNICAST_IF socket-option ids (not exported by
	// x/sys/windows).
	ipUnicastIF   = 31
	ipv6UnicastIF = 31

	// Debounce parameters for network-change notifications, borrowed from
	// WireGuard for Windows (tunnel/defaultroutemonitor.go): coalesce bursts
	// for 150ms, but never delay a re-detection beyond 2s if the burst keeps
	// going (interface storms during docking/undocking).
	debounceInterval = 150 * time.Millisecond
	debounceBurstMax = 2 * time.Second

	// sweepInterval paces the registry liveness sweep. On a stable network
	// re-apply (the other cleanup point) may not run for weeks; the sweep
	// guarantees closed sockets don't stay pinned by their RawConn either
	// way. The registry holds a handful of entries, so this is nearly free.
	sweepInterval = 2 * time.Minute
)

// windowsMarker binds libp2p (and SOCKS5 exit-node) sockets to the physical
// uplink NIC via IP_UNICAST_IF / IPV6_UNICAST_IF so their traffic bypasses
// the /1 gateway routes pointing into the TUN. Always on, like SO_MARK on
// Linux: marking sockets from process start makes a later runtime gateway
// enable safe (already-open sockets are already bound to the uplink — no
// routing loop).
//
// Unlike SO_MARK (interpreted by the kernel per packet), UNICAST_IF is frozen
// into the socket, so long-lived sockets must be re-bound when the uplink
// changes. Start launches a watcher that re-detects the uplink on network
// changes and re-applies the options across the registry of live UDP sockets
// (the eternal QUIC sockets; established TCP cannot survive an uplink change
// anyway — see sockRegistry). This is the same mechanism userspace WireGuard
// for Windows used (defaultroutemonitor + BindSocketToInterface4/6).
//
// The uplink is tracked per address family: on multihomed hosts the IPv6
// default route may live on a different NIC than the IPv4 one.
type windowsMarker struct {
	index4 atomic.Uint32
	index6 atomic.Uint32

	registry sockRegistry
	kickCh   chan struct{}
}

// newMarker returns the Windows marker. The uplink indexes stay zero (marking is a
// no-op) until Start performs the initial detection.
func newMarker() marker {
	return &windowsMarker{kickCh: make(chan struct{}, 1)}
}

func (m *windowsMarker) FWMark() uint32 { return 0 }

// Start synchronously detects the current uplink and launches the
// network-change watcher, which lives until ctx is cancelled. An offline
// start (no default route → both indexes 0) is not an error: the watcher
// picks the uplink up when connectivity appears and re-binds registered
// sockets, so a restart is never needed. Only the change-notification
// registration itself can fail.
func (m *windowsMarker) Start(ctx context.Context) error {
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

// Ready reports whether the marker currently knows an IPv4 uplink — the
// prerequisite for enabling gateway client mode without a routing loop. The
// condition is self-healing (the watcher re-binds sockets when connectivity
// appears), so a failure here means "try again once online", not "restart".
// IPv6 is not required: the tunnel is IPv4-only and gateway mode fences IPv6.
//
// TODO(gateway-offline-start): soften this gate to a warning so gateway
// client mode can be enabled/booted offline and self-heal when connectivity appears
func (m *windowsMarker) Ready() error {
	if m.index4.Load() == 0 {
		return errors.New("no active network connection (no IPv4 default route)")
	}
	return nil
}

func (m *windowsMarker) ControlFunc() func(network, address string, c syscall.RawConn) error {
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
		ctrlErr, sockErr := m.apply(network, address, c, false)
		if ctrlErr != nil {
			return fmt.Errorf("sockmark control: %w", ctrlErr)
		}
		if sockErr != nil {
			return fmt.Errorf("sockmark: %w", sockErr)
		}
		return nil
	}
}

// apply sets the UNICAST_IF options on one socket. reapply=false (socket
// creation) skips families whose index is unknown — the option simply stays
// unset. reapply=true (uplink change) always writes, because writing 0 is the
// documented way to clear a stale binding (the socket falls back to regular
// routing, which is safe: with no uplink there is nothing to leak to, and
// Ready() blocks enabling the gateway while offline).
//
// Returns the Control-level error (dead socket — eviction signal for the
// registry) separately from setsockopt errors (live socket, wrong option —
// caller logs or fails the dial).
func (m *windowsMarker) apply(network, address string, c syscall.RawConn, reapply bool) (ctrlErr, sockErr error) {
	idx4 := m.index4.Load()
	idx6 := m.index6.Load()
	v4, v6, confident := unicastIFFamilies(network, address)

	var errs []error
	ctrlErr = c.Control(func(fd uintptr) {
		handle := windows.Handle(fd)
		if v6 {
			if idx6 != 0 || reapply {
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
		if v4 && (idx4 != 0 || reapply) {
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

// kick schedules a debounced uplink re-detection. Non-blocking: called from
// OS notification threads.
func (m *windowsMarker) kick() {
	select {
	case m.kickCh <- struct{}{}:
	default:
	}
}

// watch is the marker's background goroutine: debounced re-detection on
// network change notifications plus the periodic registry sweep. cleanup
// unregisters the OS callbacks when ctx dies.
//
// TODO(netstate): the callback → debounce → redetect → setsockopt chain has
// no integration coverage (unit tests cover only the registry logic; the
// Linux counterpart R4/R5 hostnet tests cover the routes monitor, which has
// no Windows analogue — the re-bind IS the Windows reaction to route
// changes). Add a hostnet-style test — Start → socket via ControlFunc →
// mutate default routes → assert getsockopt(IP_UNICAST_IF) — after the
// monitor moves into the netstate manager
func (m *windowsMarker) watch(ctx context.Context, cleanup func()) {
	defer cleanup()

	coalesce := time.NewTimer(time.Hour)
	if !coalesce.Stop() {
		<-coalesce.C
	}
	defer coalesce.Stop()
	sweep := time.NewTicker(sweepInterval)
	defer sweep.Stop()

	stopCoalesce := func() {
		if !coalesce.Stop() {
			select {
			case <-coalesce.C:
			default:
			}
		}
	}

	var burstStart time.Time
	pending := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.kickCh:
			now := time.Now()
			switch {
			case !pending:
				burstStart = now
				pending = true
				coalesce.Reset(debounceInterval)
			case now.Sub(burstStart) >= debounceBurstMax:
				// The burst has been going on too long — don't starve the
				// re-detection, run it now.
				stopCoalesce()
				pending = false
				m.redetect()
			default:
				stopCoalesce()
				coalesce.Reset(debounceInterval)
			}
		case <-coalesce.C:
			pending = false
			m.redetect()
		case <-sweep.C:
			if evicted := m.registry.sweep(); evicted > 0 {
				logger.Debugf("registry sweep evicted %d closed sockets", evicted)
			}
		}
	}
}

// redetect recomputes both uplink indexes and, on change, re-binds every
// registered socket.
func (m *windowsMarker) redetect() {
	idx4, idx6 := detectUplinkIndexes()
	old4 := m.index4.Swap(idx4)
	old6 := m.index6.Swap(idx6)
	if old4 == idx4 && old6 == idx6 {
		return
	}
	logger.Infof("uplink changed: IPv4 ifIndex %d -> %d, IPv6 ifIndex %d -> %d (re-binding %d sockets)",
		old4, idx4, old6, idx6, m.registry.size())
	m.reapply()
}

// reapply re-binds all registered sockets to the current indexes. Sockets
// whose fd is dead (Control fails) are evicted.
func (m *windowsMarker) reapply() {
	m.registry.forEachLive(func(e *registryEntry) error {
		ctrlErr, sockErr := m.apply(e.network, e.address, e.conn, true)
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
func detectUplinkIndexes() (idx4, idx6 uint32) {
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
