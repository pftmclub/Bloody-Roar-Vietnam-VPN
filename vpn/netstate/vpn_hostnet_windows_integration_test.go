//go:build windows && vpn_hostnet

// Package netstate host-network integration tests, Windows edition.
//
// These tests exercise the real Windows plumbing behind Manager
// (EnableServerNAT/DisableServerNAT and EnableClientRoutes/
// DisableClientRoutes) against the *actual* host network: they create WinNAT
// instances, WFP filters, flip per-interface forwarding, spawn a real Wintun
// adapter and install /1 routes on it.
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
//   - client-route stale recovery / leftover collisions (Linux R2/R3):
//     impossible by design — the routes die with the adapter LUID
//     (TestGatewayHostNetClientRoutesDieWithAdapter proves exactly that),
//     and a fresh adapter is a fresh LUID.
//
// The Windows counterpart of the Linux route-change reaction (R4/R5) is the
// marker re-bind, covered by TestGatewayHostNetMarkerRebind below — with a
// poisoned index, not a real network mutation (see the test comment). Honest
// mutation of the runner's network (NIC metric flip and the resulting OS
// callbacks) remains a manual-pass scenario.
package netstate

import (
	"context"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"syscall"
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

// startManager runs Manager.Start with a test-scoped context, populating the
// uplink indexes the same way production does. The watch goroutine dies on
// the context cancel registered here; verifyNoLeaks (registered before this,
// so running after) sees it gone. Skips when the host is offline: enabling
// offline is allowed (warn + self-heal), but the tests below assert against
// a real uplink index (e.g. MarkerRebind), which an offline runner cannot
// provide.
func startManager(t *testing.T, mgr *Manager) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	require.NoError(t, mgr.Start(ctx))
	if mgr.index4.Load() == 0 {
		t.Skip("no IPv4 uplink on this host; these tests assert against a real uplink index")
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

// ---- Marker: watcher re-binds registered sockets on uplink change ----

// rawConn extracts the RawConn of a UDP socket for direct sockopt access.
func rawConn(t *testing.T, conn net.PacketConn) syscall.RawConn {
	t.Helper()
	udp, ok := conn.(*net.UDPConn)
	require.True(t, ok)
	raw, err := udp.SyscallConn()
	require.NoError(t, err)
	return raw
}

// getUnicastIF4 reads IP_UNICAST_IF off a socket. Winsock is asymmetric here:
// setsockopt takes the index in network byte order (see bindSocketToUplink),
// but getsockopt returns it in host byte order — no conversion needed
// (verified empirically on a real Winsock: set(htonl(14)) reads back as 14).
func getUnicastIF4(t *testing.T, conn net.PacketConn) uint32 {
	t.Helper()
	var val int
	var sockErr error
	require.NoError(t, rawConn(t, conn).Control(func(fd uintptr) {
		val, sockErr = windows.GetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIF)
	}))
	require.NoError(t, sockErr)
	return uint32(val)
}

// setUnicastIF4 writes IP_UNICAST_IF directly (bypassing the Manager), used to
// plant a stale binding.
func setUnicastIF4(t *testing.T, conn net.PacketConn, ifIndex uint32) {
	t.Helper()
	var sockErr error
	require.NoError(t, rawConn(t, conn).Control(func(fd uintptr) {
		sockErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIF,
			int(bits.ReverseBytes32(ifIndex)))
	}))
	require.NoError(t, sockErr)
}

// TestGatewayHostNetMarkerRebind exercises the notifyNetChange → debounce →
// redetectUplinks → rebindSockets chain end to end on a real Winsock socket:
// a registered UDP socket whose binding went stale must be re-bound to the
// live uplink after a network-change notification.
//
// The stored index is poisoned to 0 (and the socket's binding cleared) before
// the notification — without that the test would prove nothing:
// redetectUplinks returns before rebindSockets when the re-computed indexes
// match the stored ones, and the runner's network does not change between
// Start and the notification, so the socket would simply keep the correct
// binding it received at creation. Poisoning to 0 is also the realistic
// shape: it is exactly the offline→online transition.
//
// Assertions go through Eventually on the final state only: the OS callbacks
// registered by Start are live, so background network events may race our
// notification with an identical re-detection — same chain, same outcome.
func TestGatewayHostNetMarkerRebind(t *testing.T) {
	verifyNoLeaks(t)
	mgr := NewManager()
	startManager(t, mgr)
	realIdx := mgr.index4.Load()

	lc := net.ListenConfig{Control: mgr.ControlFunc()}
	conn, err := lc.ListenPacket(context.Background(), "udp4", ":0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	require.Equal(t, realIdx, getUnicastIF4(t, conn),
		"a socket created while the uplink is known must be bound at creation")

	// Plant the stale state: the socket unbound, the manager convinced there
	// is no uplink.
	setUnicastIF4(t, conn, 0)
	mgr.index4.Store(0)

	mgr.notifyNetChange()

	require.Eventually(t, func() bool {
		return getUnicastIF4(t, conn) == realIdx
	}, 5*time.Second, 50*time.Millisecond,
		"the watcher must re-detect the uplink and re-bind the registered socket")
}

// ---- Server: NAT lifecycle ----

func TestGatewayHostNetNATLifecycle(t *testing.T) {
	verifyNoLeaks(t)
	requireAdmin(t)
	nicLUID, nicGUID := pickServerTestNIC(t)

	forwardingBefore := forwardingEnabled(t, nicLUID)
	require.False(t, awlNATInstalled(t), "pre-existing awl-gateway NetNat; clean the host before running")

	mgr := NewManager()
	require.NoError(t, mgr.EnableServerNAT(testAwlSubnet, nicGUID))
	require.True(t, mgr.ServerNATActive())

	require.True(t, awlNATInstalled(t), "NetNat must exist while NAT is up")
	require.True(t, forwardingEnabled(t, nicLUID), "forwarding must be on while NAT is up")
	require.True(t, wfpRuleInstalled(t), "WFP block rule must be installed while NAT is up")

	require.NoError(t, mgr.DisableServerNAT())
	require.False(t, mgr.ServerNATActive())

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

	mgr := NewManager()
	require.NoError(t, mgr.EnableServerNAT(testAwlSubnet, nicGUID))
	require.True(t, forwardingEnabled(t, nicLUID))

	require.NoError(t, mgr.DisableServerNAT())
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

	mgr := NewManager()
	require.NoError(t, mgr.EnableServerNAT(testAwlSubnet, nicGUID),
		"EnableServerNAT must recover from a stale awl-gateway NetNat")
	require.True(t, awlNATInstalled(t))

	require.NoError(t, mgr.DisableServerNAT())
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

	mgr := NewManager()
	err = mgr.EnableServerNAT(testAwlSubnet, nicGUID)
	if err == nil {
		// If even overlapping-prefix instances are tolerated, there is no
		// failure to roll back from. Clean up and skip rather than fail.
		require.NoError(t, mgr.DisableServerNAT())
		t.Skip("this host allows overlapping WinNAT instances; rollback path not reachable here")
	}
	require.Contains(t, err.Error(), "WinNAT", "failure must come from the WinNAT step")
	require.False(t, mgr.ServerNATActive(), "a failed enable must leave the manager inactive")

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
	mgr := NewManager()
	startManager(t, mgr)
	tunLUID, tunGUID, _ := createTestTUN(t)

	require.NoError(t, mgr.EnableClientRoutes(tunGUID))
	require.True(t, mgr.ClientRoutesActive())
	// Egress of this host is now captured by the /1 routes into a TUN nobody
	// reads — a black hole until teardown a few lines down.

	routes := tunRoutes(t, tunLUID)
	require.Contains(t, routes, "0.0.0.0/1")
	require.Contains(t, routes, "128.0.0.0/1")
	if tunHasIPv6(tunLUID) {
		require.Contains(t, routes, "::/1", "IPv6 fence must be installed when the adapter has a v6 stack")
		require.Contains(t, routes, "8000::/1")
	}

	require.NoError(t, mgr.DisableClientRoutes())
	require.False(t, mgr.ClientRoutesActive())

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
	mgr := NewManager()
	startManager(t, mgr)
	tunLUID, tunGUID, device := createTestTUN(t)

	require.NoError(t, mgr.EnableClientRoutes(tunGUID))
	require.Contains(t, tunRoutes(t, tunLUID), "0.0.0.0/1")

	// Simulate the crash: no teardown, just kill the adapter.
	require.NoError(t, device.Close())

	// The IP stack may take a moment to drop the interface's routes.
	require.Eventually(t, func() bool {
		return len(tunRoutes(t, tunLUID)) == 0
	}, 15*time.Second, 200*time.Millisecond,
		"all routes bound to the dead adapter must disappear")
}
