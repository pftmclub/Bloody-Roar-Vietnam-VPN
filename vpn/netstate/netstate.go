// Package netstate owns the platform-specific OS network state behind AWL's
// VPN gateway feature:
//
//   - Socket marking (marker): keeps libp2p and SOCKS5 exit-node traffic out
//     of the VPN tunnel so gateway mode cannot loop it back into itself.
//     Linux: SO_MARK + ip-rule policy routing. Android: VpnService.protect()
//     callback supplied by the host app. Windows: IP_UNICAST_IF binding to
//     the physical uplink NIC. Other platforms: no-op.
//   - Client-side gateway routes (setupGatewayRoutes/teardownGatewayRoutes):
//     the TUN default route plus the IPv6 fail-closed fence.
//   - Server-side exit-node NAT (setupNAT/teardownNAT): forwarding, address
//     translation and the LAN/CGNAT isolation filter.
//   - Uplink detection: picking the physical interface carrying the best
//     default route, shared by socket marking and server NAT.
//
// All of it is owned by a single Manager instance (created via NewManager, or
// NewAndroidManager on Android): the Application starts it once per process
// and feeds its ControlFunc to the libp2p host config; the gateway service
// applies and reverts the client routes / server NAT through it at runtime.
package netstate

// awlMark is the numeric value shared on Linux by the SO_MARK fwmark applied
// to marked sockets and the policy-routing table ID holding their exemption
// routes. 0x61776C = "awl" in ASCII (lowercase). The two live in different
// kernel namespaces and don't collide; using one value makes awl-owned state
// trivially greppable in `ip rule` / `ip route show table`.
const awlMark = 0x61776C
