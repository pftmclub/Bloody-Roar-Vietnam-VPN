package routes

import (
	"fmt"
	"net/netip"
)

// privateSubnets is the destination set we refuse to forward from the gateway,
// so the exit node's LAN, link-local, and CGNAT space stay invisible to
// clients. awlSubnet itself is contained in 10.0.0.0/8 in practice, so
// awl↔awl forward through the gateway is also dropped here — by design:
// peers reach each other directly via libp2p, not via routed IP through an
// exit node.
//
// Shared across platforms: Linux feeds the strings to iptables as-is,
// Windows parses them into netip.Prefix for the WFP forward-layer filter.
var privateSubnets = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",  // RFC 6598 — CGNAT
	"169.254.0.0/16", // RFC 3927 — link-local
}

// privateSubnetPrefixes returns privateSubnets parsed into netip.Prefix.
// Panics on a malformed entry — the list is a compile-time constant and is
// verified by a unit test, so a panic here means a broken edit, not runtime
// input.
func privateSubnetPrefixes() []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(privateSubnets))
	for _, s := range privateSubnets {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			panic(fmt.Sprintf("privateSubnets contains malformed prefix %q: %v", s, err))
		}
		prefixes = append(prefixes, p)
	}
	return prefixes
}
