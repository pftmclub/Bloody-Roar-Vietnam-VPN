//go:build windows

package netstate

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// routeState holds the state needed to teardown gateway routes on Windows.
type routeState struct {
	tunLUID winipcfg.LUID
	routes  []winipcfg.MibIPforwardRow2
}

// setupGatewayRoutes configures the gateway client routes on Windows:
//
//   - 0.0.0.0/1 + 128.0.0.0/1 via the TUN. More specific than the existing /0
//     default, so they win longest-prefix-match without replacing it.
//   - ::/1 + 8000::/1 via the TUN — the IPv6 fail-closed fence. awl does not
//     tunnel IPv6 (HandleReadPackets drops IsIPv6), so captured v6 packets die
//     in userspace instead of leaking around the gateway. Installed
//     unconditionally rather than "if v6 connectivity exists": both the v6
//     address and the ::/0 default arrive from RA (SLAAC), so at enable time
//     they may not exist yet and appear seconds later — a presence check
//     would be fail-open. If route creation fails because the TUN adapter
//     simply has no IPv6 stack (disabled system-wide), that is tolerated with
//     a warning; any other failure fails the setup (fail-closed).
//
// Crash semantics: all these routes are bound to the TUN LUID, so after
// kill -9 they die with the Wintun adapter — fail-open until restart for both
// families (on Linux the v6 fence survives a crash; Windows is weaker here,
// documented in GATEWAY_FEATURE.md).
//
// fwmark is unused on Windows — sockets are bound to the physical interface
// via IP_UNICAST_IF; see sockmark_windows.go.
func setupGatewayRoutes(tunIfName string, fwmark uint32) (*routeState, error) {
	luid, err := luidFromGUIDName(tunIfName)
	if err != nil {
		return nil, fmt.Errorf("resolve TUN interface: %w", err)
	}

	state := &routeState{
		tunLUID: luid,
	}

	v4Prefixes := []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
	for _, prefix := range v4Prefixes {
		if err := state.addTunRoute(prefix, netip.IPv4Unspecified()); err != nil {
			_ = teardownGatewayRoutes(state)
			return nil, err
		}
	}

	v6Prefixes := []netip.Prefix{
		netip.MustParsePrefix("::/1"),
		netip.MustParsePrefix("8000::/1"),
	}
	for _, prefix := range v6Prefixes {
		err := state.addTunRoute(prefix, netip.IPv6Unspecified())
		if err == nil {
			continue
		}
		if !tunHasIPv6(luid) {
			// The same condition that makes setInterfaceMTU(AF_INET6) fail at
			// TUN creation: no v6 stack on the adapter means no v6 to fence.
			logger.Warnf("skipping IPv6 fail-closed fence: IPv6 appears disabled on the TUN adapter (%v)", err)
			break
		}
		// v6 exists on the adapter but the fence could not be installed —
		// continuing would silently leak IPv6 around the gateway.
		_ = teardownGatewayRoutes(state)
		return nil, fmt.Errorf("install IPv6 fail-closed fence: %w", err)
	}

	return state, nil
}

// addTunRoute creates one on-link route (unspecified next hop) via the TUN
// and records it for teardown.
func (state *routeState) addTunRoute(prefix netip.Prefix, nextHop netip.Addr) error {
	row := winipcfg.MibIPforwardRow2{}
	// InitializeIpForwardEntry is mandatory before CreateIpForwardEntry2
	// it sets ValidLifetime/PreferredLifetime to infinite and Protocol to NetMgmt.
	// Without it the route lands in the table with zero lifetimes and is
	// ignored by the forwarding path — visible in Get-NetRoute, yet traffic
	// keeps flowing past it.
	row.Init()
	row.InterfaceLUID = state.tunLUID
	row.DestinationPrefix.PrefixLength = uint8(prefix.Bits())
	if err := row.DestinationPrefix.RawPrefix.SetAddr(prefix.Addr()); err != nil {
		return fmt.Errorf("set destination prefix %s: %w", prefix, err)
	}
	// NextHop: unspecified addr = on-link (point-to-point TUN)
	if err := row.NextHop.SetAddr(nextHop); err != nil {
		return fmt.Errorf("set next hop for %s: %w", prefix, err)
	}
	row.Metric = 5 // low metric = high priority

	if err := row.Create(); err != nil {
		return fmt.Errorf("add route %s: %w", prefix, err)
	}
	state.routes = append(state.routes, row)
	return nil
}

// tunHasIPv6 reports whether the adapter has an IPv6 interface row — absent
// when IPv6 is disabled on the adapter or system-wide.
func tunHasIPv6(luid winipcfg.LUID) bool {
	_, err := luid.IPInterface(windows.AF_INET6)
	return err == nil
}

// teardownGatewayRoutes removes the routes added by setupGatewayRoutes.
func teardownGatewayRoutes(state *routeState) error {
	if state == nil {
		return nil
	}

	var errs []error
	for _, row := range state.routes {
		if err := row.Delete(); err != nil {
			errs = append(errs, fmt.Errorf("del route: %w", err))
		}
	}
	state.routes = nil

	return errors.Join(errs...)
}

// luidFromGUIDName resolves an interface name as used by awl on Windows — a
// GUID string like "{13b1820f-...}" (see vpn.Device.InterfaceName) — into a
// winipcfg.LUID. Fails if the adapter does not currently exist.
//
// The LUID is technically already known where the TUN is created
// (vpn/iface_windows.go, NativeTun.LUID()), but the routes/NAT API carries
// the interface identity as a platform-neutral string ("awl0" on Linux, the
// GUID here) through cross-platform service code, so we convert back. That's
// two cheap lookups (ConvertInterfaceGuidToLuid) once per gateway enable —
// cheaper than windows-only plumbing through service/vpn_gateway.go.
func luidFromGUIDName(ifName string) (winipcfg.LUID, error) {
	guid, err := windows.GUIDFromString(ifName)
	if err != nil {
		return 0, fmt.Errorf("parse interface GUID %q: %w", ifName, err)
	}
	luid, err := winipcfg.LUIDFromGUID(&guid)
	if err != nil {
		return 0, fmt.Errorf("resolve LUID for %s: %w", ifName, err)
	}
	return luid, nil
}
