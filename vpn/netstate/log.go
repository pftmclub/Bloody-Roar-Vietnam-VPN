package netstate

import "github.com/ipfs/go-log/v2"

// logger is the shared package-level logger (socket marker, gateway routes,
// NAT). Used to surface stale-state recovery, uplink changes and other one-off
// events that callers shouldn't have to thread through return values.
var logger = log.Logger("awl/vpn/netstate")
