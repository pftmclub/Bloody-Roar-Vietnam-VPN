package sockmark

import (
	"net"
	"net/netip"
	"strings"
)

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
