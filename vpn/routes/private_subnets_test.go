package routes

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPrivateSubnetsParse pins the invariant privateSubnetPrefixes relies on:
// every entry in privateSubnets is a valid CIDR (the function panics
// otherwise, by design — the list is a compile-time constant).
func TestPrivateSubnetsParse(t *testing.T) {
	prefixes := privateSubnetPrefixes()
	require.Len(t, prefixes, len(privateSubnets))
	for i, p := range prefixes {
		require.True(t, p.IsValid(), "prefix %d (%s) must be valid", i, privateSubnets[i])
		require.True(t, p.Addr().Is4(), "prefix %d (%s) must be IPv4 — the WFP filter is v4-only", i, privateSubnets[i])
		require.Equal(t, p.Masked(), p, "prefix %d (%s) must be in canonical masked form", i, privateSubnets[i])
	}
}
