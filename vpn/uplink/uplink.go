// Package uplink picks the host's physical uplink interface from the routing
// table: the interface carrying the best default route, excluding our own TUN.
//
// Shared by vpn/sockmark (binding libp2p sockets to the physical NIC on
// Windows via IP_UNICAST_IF) and vpn/routes (enabling per-interface forwarding
// on the exit node). The selection itself is a pure function over a
// platform-neutral snapshot so it can be unit-tested everywhere; building the
// snapshot from the live routing table is platform-specific (see
// uplink_windows.go).
//
// The algorithm mirrors WireGuard for Windows (findDefaultLUID in
// tunnel/mtumonitor.go): among default routes (PrefixLength == 0) on
// operationally-up interfaces, excluding our own adapter, pick the lowest
// (route metric + interface metric).
package uplink

// Route is a snapshot of one default-route candidate.
type Route struct {
	// IfLUID identifies the interface (winipcfg.LUID on Windows). Opaque here;
	// only used for the exclusion match and for returning the winner.
	IfLUID uint64
	// IfIndex is the interface index used for IP_UNICAST_IF / IPV6_UNICAST_IF.
	IfIndex uint32
	// Metric is the effective priority: route metric + interface metric.
	Metric uint32
	// Up reports whether the interface is operationally up.
	Up bool
}

// Best returns the candidate with the lowest Metric among routes that are Up
// and whose IfLUID differs from excludeLUID. Returns ok=false when no
// candidate qualifies (offline host, or the only default route is our own
// TUN). Ties are broken by first occurrence, matching table order.
func Best(routes []Route, excludeLUID uint64) (Route, bool) {
	var best Route
	found := false
	for _, r := range routes {
		if !r.Up || r.IfLUID == excludeLUID {
			continue
		}
		if !found || r.Metric < best.Metric {
			best = r
			found = true
		}
	}
	return best, found
}
