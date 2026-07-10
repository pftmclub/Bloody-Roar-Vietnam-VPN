//go:build windows

package netstate

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	wfpSublayerName = "awl-gateway"
	wfpRuleName     = "awl-gateway: block forwarded LAN/CGNAT egress from TUN"
)

// NATState holds the state needed to teardown NAT on Windows.
//
// Crash semantics (kill -9): the WFP session below is Dynamic, so the kernel
// removes its sublayer and filter the moment the process dies — no stale
// firewall state is possible. The WinNAT instance and the forwarding flags do
// survive a crash, but they cannot cause transit on their own: the exit-node
// data path runs through this userspace process (libp2p → TUN write) and the
// Wintun adapter disappears with it. The leftover NetNat is removed by
// stale-recovery on the next SetupNAT; the forwarding flags are left as-is
// forever — their provenance is unknown after a crash (the next run sees
// "enabled" and treats it as "was already enabled"), same caveat as the Linux
// ip_forward handling.
type NATState struct {
	natCreated bool
	wfpSession *wf.Session
	// forwardingEnabled lists interfaces where WE flipped IPv4 forwarding on
	// (it was off before SetupNAT). Only these are reverted at teardown.
	forwardingEnabled []winipcfg.LUID
}

// SetupNAT configures the Windows exit node: a WFP forward-layer filter that
// keeps clients out of the exit node's LAN/CGNAT space, per-interface IPv4
// forwarding on the TUN and the uplink, and a WinNAT instance providing
// MASQUERADE-style translation for the awl subnet.
//
// Order matters and is fail-closed: the WFP BLOCK filter is installed before
// forwarding/NAT create any technical possibility of transit. Any failure
// after the first step rolls back via TeardownNAT (all steps are idempotent).
func SetupNAT(awlSubnet, tunIfName string) (*NATState, error) {
	awlPrefix, err := netip.ParsePrefix(awlSubnet)
	if err != nil {
		return nil, fmt.Errorf("parse awl subnet %q: %w", awlSubnet, err)
	}
	tunLUID, err := luidFromGUIDName(tunIfName)
	if err != nil {
		return nil, fmt.Errorf("resolve TUN interface: %w", err)
	}
	tunIfRow, err := tunLUID.Interface()
	if err != nil {
		return nil, fmt.Errorf("query TUN interface row: %w", err)
	}
	tunIfIndex := tunIfRow.InterfaceIndex

	// Stale recovery: a previous run killed before TeardownNAT leaves its
	// NetNat behind (WFP leftovers are impossible — dynamic session). Remove
	// it so New-NetNat below gets a clean slate.
	cleaned, err := cleanupStaleWinNAT()
	if err != nil {
		return nil, fmt.Errorf("pre-clean stale WinNAT: %w", err)
	}
	if cleaned {
		logger.Warnf("recovered from leftover gateway NAT state (previous run was likely killed before teardown)")
	}

	state := &NATState{}

	// 1. WFP forward-layer BLOCK — the safety fence goes up first.
	if err := setupWFP(state, tunIfIndex, awlPrefix); err != nil {
		_ = TeardownNAT(state)
		return nil, fmt.Errorf("setup WFP filter: %w", err)
	}

	// 2. Per-interface IPv4 forwarding on TUN + uplink. The uplink is the
	// interface holding the best default route right now; if the host is
	// offline we still bring the server up (parity with Linux, where
	// ServerEnabled is applied at startup regardless of connectivity) and
	// only warn — transit starts working when SetupNAT next runs with a
	// live uplink.
	//
	// TODO(netstate): if the uplink changes mid-session (or appears after an
	// offline start), the new uplink keeps its own forwarding value and
	// transit needs a gateway server off/on toggle.
	// Fix is a route-change subscriber that re-syncs
	// forwarding on the new uplink; lands with the netstate refactoring
	forwardingTargets := []winipcfg.LUID{tunLUID}
	route, ok, err := bestUplinkDefault(windows.AF_INET, tunLUID)
	if err != nil {
		_ = TeardownNAT(state)
		return nil, fmt.Errorf("detect uplink for forwarding: %w", err)
	}
	if ok {
		forwardingTargets = append(forwardingTargets, winipcfg.LUID(route.IfLUID))
	} else {
		logger.Warnf("no IPv4 default route found: enabling forwarding on TUN only, " +
			"internet transit will not work until the gateway server is re-enabled with an active uplink")
	}
	for _, luid := range forwardingTargets {
		enabledByUs, err := enableIPv4Forwarding(luid)
		if err != nil {
			_ = TeardownNAT(state)
			return nil, fmt.Errorf("enable forwarding on interface %d: %w", luid, err)
		}
		if enabledByUs {
			state.forwardingEnabled = append(state.forwardingEnabled, luid)
		}
	}

	// 3. WinNAT instance — transit becomes possible only now, with the WFP
	// fence already in place.
	if err := createWinNAT(awlSubnet); err != nil {
		_ = TeardownNAT(state)
		return nil, err
	}
	state.natCreated = true

	return state, nil
}

// TeardownNAT reverses SetupNAT in reverse order: WinNAT first (internet
// transit dies), then forwarding (LAN transit dies), then the WFP session —
// the protection is removed last, when transit is no longer possible. Errors
// are collected; teardown proceeds through all steps. Safe on partial state.
func TeardownNAT(state *NATState) error {
	if state == nil {
		return nil
	}

	var errs []error
	if state.natCreated {
		if err := removeWinNAT(); err != nil {
			errs = append(errs, fmt.Errorf("remove WinNAT: %w", err))
		}
		state.natCreated = false
	}

	for _, luid := range state.forwardingEnabled {
		if err := disableIPv4Forwarding(luid); err != nil {
			errs = append(errs, fmt.Errorf("restore forwarding on interface %d: %w", luid, err))
		}
	}
	state.forwardingEnabled = nil

	if state.wfpSession != nil {
		if err := state.wfpSession.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close WFP session: %w", err))
		}
		state.wfpSession = nil
	}

	return errors.Join(errs...)
}

// setupWFP opens a dynamic WFP session and installs one BLOCK filter on the
// IPv4 forward layer:
//
//	sourceInterfaceIndex == TUN  AND  src ∈ awlSubnet  AND  dst ∈ privateSubnets
//
// (multiple conditions on one field OR together, distinct fields AND).
//
// The load-bearing condition is SOURCE_INTERFACE_INDEX: the input interface
// of a forwarded packet is not rewritten by NAT, so the block holds regardless
// of how WinNAT translation is ordered against forward-layer classification —
// the same semantics as the Linux `-i awl0` jump. src ∈ awlSubnet is the
// second belt (parity with `-s awlSubnet`).
//
// No conntrack analogue is needed: reply traffic (src external, dst ∈
// awlSubnet) enters through the uplink, not the TUN, and matches neither of
// the first two conditions.
//
// No IPv6 filter: the client does not tunnel IPv6 (writeInboundBatch drops
// IsIPv6), so IPv6 transit from awl clients does not exist.
//
// Known WFP limitation (accepted): a BLOCK from our sublayer can only be
// overridden by a hard permit (FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT) from a
// higher-weight sublayer — exotic on the forward layer; a plain PERMIT from
// another firewall does not defeat it.
//
// The session is Dynamic: everything installed here is removed by the kernel
// when the session closes or the process dies, so there is no stale-WFP
// recovery path.
func setupWFP(state *NATState, tunIfIndex uint32, awlPrefix netip.Prefix) error {
	session, err := wf.New(&wf.Options{
		Name:        "Anywherelan VPN gateway",
		Description: "Blocks forwarded traffic from awl peers to the exit node's private networks",
		Dynamic:     true,
	})
	if err != nil {
		return fmt.Errorf("open WFP session: %w", err)
	}
	// From here on the session must end up either in state (success) or
	// closed (failure) — otherwise the dynamic session (and the guarantees
	// tied to its lifetime) would dangle until process exit.

	sublayerID, err := newWFPGUID()
	if err != nil {
		_ = session.Close()
		return err
	}
	err = session.AddSublayer(&wf.Sublayer{
		ID:     wf.SublayerID(sublayerID),
		Name:   wfpSublayerName,
		Weight: 0x8000,
	})
	if err != nil {
		_ = session.Close()
		return fmt.Errorf("add WFP sublayer: %w", err)
	}

	ruleID, err := newWFPGUID()
	if err != nil {
		_ = session.Close()
		return err
	}
	conditions := []*wf.Match{
		{Field: wf.FieldSourceInterfaceIndex, Op: wf.MatchTypeEqual, Value: tunIfIndex},
		{Field: wf.FieldIPSourceAddress, Op: wf.MatchTypeEqual, Value: awlPrefix},
	}
	for _, p := range privateSubnetPrefixes() {
		conditions = append(conditions, &wf.Match{
			Field: wf.FieldIPDestinationAddress, Op: wf.MatchTypeEqual, Value: p,
		})
	}
	err = session.AddRule(&wf.Rule{
		ID:         wf.RuleID(ruleID),
		Name:       wfpRuleName,
		Layer:      wf.LayerIPForwardV4,
		Sublayer:   wf.SublayerID(sublayerID),
		Weight:     1000,
		Conditions: conditions,
		Action:     wf.ActionBlock,
	})
	if err != nil {
		_ = session.Close()
		return fmt.Errorf("add WFP block rule: %w", err)
	}

	state.wfpSession = session
	return nil
}

func newWFPGUID() (windows.GUID, error) {
	guid, err := windows.GenerateGUID()
	if err != nil {
		return windows.GUID{}, fmt.Errorf("generate GUID: %w", err)
	}
	return guid, nil
}

// enableIPv4Forwarding turns IPv4 forwarding on for one interface via
// SetIpInterfaceEntry. Returns enabledByUs=true iff it was off and we flipped
// it — mirroring the Linux ip_forward logic: interfaces that already forward
// (other VPNs, containers, ICS) are left alone at teardown too.
func enableIPv4Forwarding(luid winipcfg.LUID) (bool, error) {
	ipIface, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return false, fmt.Errorf("get IP interface: %w", err)
	}
	if ipIface.ForwardingEnabled {
		return false, nil
	}
	ipIface.ForwardingEnabled = true
	// winipcfg's IPInterface() already normalizes SitePrefixLength for the
	// SetIpInterfaceEntry quirk, so the row is safe to Set as-is.
	if err := ipIface.Set(); err != nil {
		return false, fmt.Errorf("set forwarding: %w", err)
	}
	return true, nil
}

func disableIPv4Forwarding(luid winipcfg.LUID) error {
	ipIface, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return fmt.Errorf("get IP interface: %w", err)
	}
	if !ipIface.ForwardingEnabled {
		return nil
	}
	ipIface.ForwardingEnabled = false
	if err := ipIface.Set(); err != nil {
		return fmt.Errorf("set forwarding: %w", err)
	}
	return nil
}

// runPowerShell executes one PowerShell command line. -Command is unaffected
// by execution policy; powershell.exe is present down to Server Core.
func runPowerShell(command string) ([]byte, error) {
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("powershell %q: %w (output: %s)", command, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// listNetNAT returns the current WinNAT instances.
func listNetNAT() ([]netNATEntry, error) {
	out, err := runPowerShell("Get-NetNat | Select-Object Name,InternalIPInterfaceAddressPrefix | ConvertTo-Json -Compress")
	if err != nil {
		return nil, err
	}
	return parseNetNATJSON(out)
}

// cleanupStaleWinNAT removes a leftover awl-gateway NetNat from a previous
// run that did not get a clean teardown. Returns cleaned=true iff one was
// found (and removed).
func cleanupStaleWinNAT() (bool, error) {
	entries, err := listNetNAT()
	if err != nil {
		return false, err
	}
	if _, found := findNetNAT(entries, winNATName); !found {
		return false, nil
	}
	if err := removeWinNAT(); err != nil {
		return true, err
	}
	return true, nil
}

// createWinNAT creates the awl WinNAT instance. We do not refuse preemptively
// based on Get-NetNat output — HNS-owned instances (Docker on Windows, WSL2)
// are not always visible there and multi-instance setups sometimes work — we
// try, and on failure enrich the error with the current instance list and a
// hint about the usual suspects.
func createWinNAT(awlSubnet string) error {
	cmd := fmt.Sprintf("New-NetNat -Name %s -InternalIPInterfaceAddressPrefix %s | Out-Null", winNATName, awlSubnet)
	_, err := runPowerShell(cmd)
	if err == nil {
		return nil
	}

	existing := "unavailable"
	if entries, listErr := listNetNAT(); listErr == nil {
		existing = fmt.Sprintf("%+v", entries)
	}
	return fmt.Errorf("create WinNAT instance (WinNAT is effectively single-instance per host; "+
		"existing instances, possibly from Docker/WSL2/ICS, can conflict — current Get-NetNat: %s): %w",
		existing, err)
}

func removeWinNAT() error {
	_, err := runPowerShell(fmt.Sprintf("Remove-NetNat -Name %s -Confirm:$false", winNATName))
	return err
}
