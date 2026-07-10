//go:build windows && vpn_hostnet

// Package netstate host-network integration tests, Windows edition.
//
// These tests exercise the real Windows plumbing (setupNAT/teardownNAT and
// setupGatewayRoutes/teardownGatewayRoutes) against the *actual* host
// network: they create WinNAT instances, WFP filters, flip per-interface
// forwarding, spawn a real Wintun adapter and install /1 routes on it.
//
// They are DANGEROUS by nature — while a client-route test is mid-flight the
// host's egress is captured by /1 routes pointing at a TUN nobody reads
// (a black hole until teardown). Each test tears down in the same body, but a
// panic can leave stale state. For that reason they are:
//
//   - hidden behind the `vpn_hostnet` build tag (excluded from `go test ./...`),
//   - Windows-only (`//go:build windows`),
//   - require Administrator — they fail loudly otherwise.
//
// Run them via a compiled binary (mirrors the Linux hostnet suite):
//
//	go test -c -tags vpn_hostnet -o gw-hostnet.test.exe ./vpn/netstate/
//	./gw-hostnet.test.exe -test.run '^TestGatewayHostNet' -test.v
//
// The server-side (NAT) tests use a real NIC of the host in place of the TUN:
// the code only needs an existing adapter to reference by GUID, and the WFP
// BLOCK it installs matches forwarded traffic only — harmless on a host that
// forwards nothing. The client-side (routes) tests use a real Wintun adapter
// (extracted wintun.dll from the embeds package), because /1 on-link routes
// need a point-to-point interface and their crash semantics — dying with the
// adapter — are exactly what we assert.
//
// Deliberately NOT covered here (vs the Linux suite):
//   - reaction to route changes (Linux R4/R5): on Windows that machinery is
//     the sockmark watcher (UNICAST_IF re-bind), not a routes-side monitor —
//     its integration test lands with the netstate manager refactoring,
//     see TODO(netstate) in sockmark_windows.go
//   - client-route stale recovery / leftover collisions (Linux R2/R3):
//     impossible by design — the routes die with the adapter LUID
//     (TestGatewayHostNetClientRoutesDieWithAdapter proves exactly that),
//     and a fresh adapter is a fresh LUID.
package netstate

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tailscale/wf"
	"go.uber.org/goleak"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/elevate"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"

	"github.com/anywherelan/awl/embeds"
)

const (
	testAwlSubnet = "10.66.0.0/16"
	testTunName   = "awl-hostnet-test"
)

// testTunGUID is distinct from the production vpn.WintunGUID so a test run
// never collides with a real awl instance on the same host.
var testTunGUID = mustGUID("{a1e0f9db-46cd-4b31-8e94-2f0e9a55c001}")

func mustGUID(s string) *windows.GUID {
	guid, err := windows.GUIDFromString(s)
	if err != nil {
		panic(err)
	}
	return &guid
}

func verifyNoLeaks(t *testing.T) {
	t.Helper()
	ignore := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, ignore) })
}

func requireAdmin(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("hostnet tests require Administrator; the vpn_hostnet build tag means this run is deliberate, so failing loudly instead of skipping")
	}
}

// pickServerTestNIC returns a live physical NIC to stand in for the TUN in
// NAT tests: the current uplink. Skips when the host is offline.
func pickServerTestNIC(t *testing.T) (winipcfg.LUID, string) {
	t.Helper()
	route, ok, err := bestUplinkDefault(windows.AF_INET, 0)
	require.NoError(t, err)
	if !ok {
		t.Skip("no IPv4 default route on this host; NAT hostnet tests need a live NIC")
	}
	luid := winipcfg.LUID(route.IfLUID)
	guid, err := luid.GUID()
	require.NoError(t, err)
	return luid, guid.String()
}

func forwardingEnabled(t *testing.T, luid winipcfg.LUID) bool {
	t.Helper()
	ipIface, err := luid.IPInterface(windows.AF_INET)
	require.NoError(t, err)
	return ipIface.ForwardingEnabled
}

func setForwarding(t *testing.T, luid winipcfg.LUID, enabled bool) {
	t.Helper()
	ipIface, err := luid.IPInterface(windows.AF_INET)
	require.NoError(t, err)
	ipIface.ForwardingEnabled = enabled
	require.NoError(t, ipIface.Set())
}

// wfpRuleInstalled reports whether our BLOCK rule is currently visible in the
// filtering engine, via a fresh read-only session (rules created by a dynamic
// session are visible engine-wide for its lifetime).
func wfpRuleInstalled(t *testing.T) bool {
	t.Helper()
	session, err := wf.New(&wf.Options{Name: "awl-hostnet-assert", Dynamic: true})
	require.NoError(t, err)
	defer session.Close()
	rules, err := session.Rules()
	require.NoError(t, err)
	for _, r := range rules {
		if r.Name == wfpRuleName {
			return true
		}
	}
	return false
}

func awlNATInstalled(t *testing.T) bool {
	t.Helper()
	entries, err := listNetNAT()
	require.NoError(t, err)
	_, found := findNetNAT(entries, winNATName)
	return found
}

// ---- Server: NAT lifecycle ----

func TestGatewayHostNetNATLifecycle(t *testing.T) {
	verifyNoLeaks(t)
	requireAdmin(t)
	nicLUID, nicGUID := pickServerTestNIC(t)

	forwardingBefore := forwardingEnabled(t, nicLUID)
	require.False(t, awlNATInstalled(t), "pre-existing awl-gateway NetNat; clean the host before running")

	state, err := setupNAT(testAwlSubnet, nicGUID)
	require.NoError(t, err)

	require.True(t, awlNATInstalled(t), "NetNat must exist while NAT is up")
	require.True(t, forwardingEnabled(t, nicLUID), "forwarding must be on while NAT is up")
	require.True(t, wfpRuleInstalled(t), "WFP block rule must be installed while NAT is up")

	require.NoError(t, teardownNAT(state))

	require.False(t, awlNATInstalled(t), "teardown must remove the NetNat")
	require.Equal(t, forwardingBefore, forwardingEnabled(t, nicLUID),
		"teardown must restore the interface's original forwarding state")
	require.False(t, wfpRuleInstalled(t), "teardown must remove the WFP rule (dynamic session closed)")
}

// ---- Server: teardown must not disable forwarding it did not enable ----

// TestGatewayHostNetNATPreservesExistingForwarding is the Windows counterpart
// of the Linux "pre-existing ip_forward=1 stays on" test: interfaces that
// already forward (other VPNs, containers, ICS — or a previous awl run that
// was killed, leaving the flag set) must be left alone by teardownNAT.
// Unlike the Linux test (which skips unless the host happens to have
// ip_forward pre-enabled), the per-interface flag lets us set up the
// precondition deterministically.
func TestGatewayHostNetNATPreservesExistingForwarding(t *testing.T) {
	verifyNoLeaks(t)
	requireAdmin(t)
	nicLUID, nicGUID := pickServerTestNIC(t)

	if !forwardingEnabled(t, nicLUID) {
		setForwarding(t, nicLUID, true)
		t.Cleanup(func() { setForwarding(t, nicLUID, false) })
	}

	state, err := setupNAT(testAwlSubnet, nicGUID)
	require.NoError(t, err)
	require.True(t, forwardingEnabled(t, nicLUID))

	require.NoError(t, teardownNAT(state))
	require.True(t, forwardingEnabled(t, nicLUID),
		"forwarding was already on before setup; teardown must NOT disable it")
}

// ---- Server: stale state recovery ----

func TestGatewayHostNetNATStaleRecovery(t *testing.T) {
	verifyNoLeaks(t)
	requireAdmin(t)
	nicLUID, nicGUID := pickServerTestNIC(t)
	_ = nicLUID

	// Simulate a previous run killed before teardown: NetNat left behind.
	require.NoError(t, createWinNAT(testAwlSubnet))
	require.True(t, awlNATInstalled(t))

	state, err := setupNAT(testAwlSubnet, nicGUID)
	require.NoError(t, err, "setupNAT must recover from a stale awl-gateway NetNat")
	require.True(t, awlNATInstalled(t))

	require.NoError(t, teardownNAT(state))
	require.False(t, awlNATInstalled(t))
}

// ---- Server: rollback on late-step failure ----

func TestGatewayHostNetNATRollback(t *testing.T) {
	verifyNoLeaks(t)
	requireAdmin(t)
	nicLUID, nicGUID := pickServerTestNIC(t)

	forwardingBefore := forwardingEnabled(t, nicLUID)

	// Provoke a New-NetNat failure at the last setup step by occupying WinNAT
	// with a conflicting instance whose internal prefix CONTAINS the awl one
	// (10.66.0.0/15 ⊃ 10.66.0.0/16). Windows Server images tolerate multiple
	// instances with disjoint prefixes (observed on the GitHub runner), but
	// overlapping prefixes are rejected — which is exactly the failure we
	// need at the last step.
	const conflictName = "awl-hostnet-conflict"
	_, err := runPowerShell(fmt.Sprintf(
		"New-NetNat -Name %s -InternalIPInterfaceAddressPrefix 10.66.0.0/15 | Out-Null", conflictName))
	require.NoError(t, err, "creating the conflicting NetNat must succeed on a clean host")
	t.Cleanup(func() {
		_, _ = runPowerShell(fmt.Sprintf("Remove-NetNat -Name %s -Confirm:$false", conflictName))
	})

	state, err := setupNAT(testAwlSubnet, nicGUID)
	if err == nil {
		// If even overlapping-prefix instances are tolerated, there is no
		// failure to roll back from. Clean up and skip rather than fail.
		require.NoError(t, teardownNAT(state))
		t.Skip("this host allows overlapping WinNAT instances; rollback path not reachable here")
	}
	require.Contains(t, err.Error(), "WinNAT", "failure must come from the WinNAT step")

	require.False(t, awlNATInstalled(t), "no awl-gateway NetNat may remain after rollback")
	require.Equal(t, forwardingBefore, forwardingEnabled(t, nicLUID),
		"rollback must restore the interface's original forwarding state")
	require.False(t, wfpRuleInstalled(t), "rollback must close the WFP session")
}

// ---- Client: /1 routes lifecycle on a real Wintun ----

// createTestTUN spawns a throwaway Wintun adapter and returns its LUID and
// GUID string (the interface name in awl's convention). Closed via t.Cleanup;
// closing is idempotent for tests that close it manually.
func createTestTUN(t *testing.T) (winipcfg.LUID, string, tun.Device) {
	t.Helper()
	embeds.EmbedWintun()

	tun.WintunTunnelType = "AnywherelanTest"

	var device tun.Device
	err := elevate.DoAsSystem(func() error {
		var err error
		device, err = tun.CreateTUNWithRequestedGUID(testTunName, testTunGUID, 1420)
		return err
	})
	require.NoError(t, err, "create test Wintun adapter (is wintun.dll extraction working?)")
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = device.Close()
		}
	})

	nativeTun := device.(*tun.NativeTun)
	luid := winipcfg.LUID(nativeTun.LUID())
	guid, err := luid.GUID()
	require.NoError(t, err)

	// Assign the awl IP so the adapter is a plausible stand-in for production.
	err = luid.SetIPAddresses([]netip.Prefix{netip.MustParsePrefix("10.66.0.2/16")})
	require.NoError(t, err)

	return luid, guid.String(), device
}

// tunRoutes returns all routes bound to the LUID as "prefix" strings, both
// families.
func tunRoutes(t *testing.T, luid winipcfg.LUID) []string {
	t.Helper()
	var found []string
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		rows, err := winipcfg.GetIPForwardTable2(family)
		require.NoError(t, err)
		for i := range rows {
			if rows[i].InterfaceLUID != luid {
				continue
			}
			prefix := rows[i].DestinationPrefix.Prefix()
			found = append(found, prefix.String())
		}
	}
	return found
}

func TestGatewayHostNetClientRoutesLifecycle(t *testing.T) {
	verifyNoLeaks(t)
	requireAdmin(t)
	tunLUID, tunGUID, _ := createTestTUN(t)

	state, err := setupGatewayRoutes(tunGUID, 0)
	require.NoError(t, err)
	// Egress of this host is now captured by the /1 routes into a TUN nobody
	// reads — a black hole until teardown a few lines down.

	routes := tunRoutes(t, tunLUID)
	require.Contains(t, routes, "0.0.0.0/1")
	require.Contains(t, routes, "128.0.0.0/1")
	if tunHasIPv6(tunLUID) {
		require.Contains(t, routes, "::/1", "IPv6 fence must be installed when the adapter has a v6 stack")
		require.Contains(t, routes, "8000::/1")
	}

	require.NoError(t, teardownGatewayRoutes(state))

	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"} {
		require.NotContains(t, tunRoutes(t, tunLUID), prefix,
			"teardown must remove every gateway route")
	}
}

// TestGatewayHostNetClientRoutesDieWithAdapter pins the documented crash
// semantics: the /1 routes are bound to the adapter LUID, so when the process
// dies (adapter disappears) the routes disappear with it — no dangling /1
// entries survive a kill -9.
func TestGatewayHostNetClientRoutesDieWithAdapter(t *testing.T) {
	verifyNoLeaks(t)
	requireAdmin(t)
	tunLUID, tunGUID, device := createTestTUN(t)

	_, err := setupGatewayRoutes(tunGUID, 0)
	require.NoError(t, err)
	require.Contains(t, tunRoutes(t, tunLUID), "0.0.0.0/1")

	// Simulate the crash: no teardown, just kill the adapter.
	require.NoError(t, device.Close())

	// The IP stack may take a moment to drop the interface's routes.
	require.Eventually(t, func() bool {
		return len(tunRoutes(t, tunLUID)) == 0
	}, 15*time.Second, 200*time.Millisecond,
		"all routes bound to the dead adapter must disappear")
}
