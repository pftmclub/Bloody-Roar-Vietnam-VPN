//go:build windows

package netstate

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// fakeEnable records enableIPv4Forwarding calls and plays back a scripted
// result.
type fakeEnable struct {
	calls       []winipcfg.LUID
	enabledByUs bool
	err         error
}

func (f *fakeEnable) fn(luid winipcfg.LUID) (bool, error) {
	f.calls = append(f.calls, luid)
	return f.enabledByUs, f.err
}

func TestResyncForwarding(t *testing.T) {
	const (
		uplinkA = winipcfg.LUID(101)
		uplinkB = winipcfg.LUID(202)
	)
	route := func(luid winipcfg.LUID) uplinkRoute {
		return uplinkRoute{IfLUID: uint64(luid), IfIndex: 7, Metric: 10, Up: true}
	}

	tests := []struct {
		name   string
		state  natState
		route  uplinkRoute
		ok     bool
		enable fakeEnable

		wantCalls      []winipcfg.LUID
		wantUplink     winipcfg.LUID
		wantForwarding []winipcfg.LUID
	}{
		{
			name:       "no uplink keeps state as-is (roamed offline: abandoned uplink stays enabled)",
			state:      natState{uplinkLUID: uplinkA, forwardingEnabled: []winipcfg.LUID{uplinkA}},
			ok:         false,
			wantCalls:  nil,
			wantUplink: uplinkA, wantForwarding: []winipcfg.LUID{uplinkA},
		},
		{
			name:       "same uplink is a no-op (externally flipped-off forwarding is not healed)",
			state:      natState{uplinkLUID: uplinkA},
			route:      route(uplinkA),
			ok:         true,
			wantCalls:  nil,
			wantUplink: uplinkA, wantForwarding: nil,
		},
		{
			name:       "uplink appears after offline start: enabled and recorded for teardown",
			state:      natState{uplinkLUID: 0},
			route:      route(uplinkB),
			ok:         true,
			enable:     fakeEnable{enabledByUs: true},
			wantCalls:  []winipcfg.LUID{uplinkB},
			wantUplink: uplinkB, wantForwarding: []winipcfg.LUID{uplinkB},
		},
		{
			name:       "roam to an uplink that already forwards: adopted but not recorded (not ours to revert)",
			state:      natState{uplinkLUID: uplinkA, forwardingEnabled: []winipcfg.LUID{uplinkA}},
			route:      route(uplinkB),
			ok:         true,
			enable:     fakeEnable{enabledByUs: false},
			wantCalls:  []winipcfg.LUID{uplinkB},
			wantUplink: uplinkB, wantForwarding: []winipcfg.LUID{uplinkA},
		},
		{
			name:       "enable failure leaves uplinkLUID unchanged so the next event retries",
			state:      natState{uplinkLUID: uplinkA},
			route:      route(uplinkB),
			ok:         true,
			enable:     fakeEnable{err: errors.New("boom")},
			wantCalls:  []winipcfg.LUID{uplinkB},
			wantUplink: uplinkA, wantForwarding: nil,
		},
		{
			name: "roam back to an uplink we enabled before: no duplicate teardown entry",
			state: natState{
				uplinkLUID:        uplinkB,
				forwardingEnabled: []winipcfg.LUID{uplinkA, uplinkB},
			},
			route:      route(uplinkA),
			ok:         true,
			enable:     fakeEnable{enabledByUs: true},
			wantCalls:  []winipcfg.LUID{uplinkA},
			wantUplink: uplinkA, wantForwarding: []winipcfg.LUID{uplinkA, uplinkB},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := tc.state
			resyncForwarding(&state, tc.route, tc.ok, tc.enable.fn)

			require.Equal(t, tc.wantCalls, tc.enable.calls, "enable calls")
			require.Equal(t, tc.wantUplink, state.uplinkLUID, "uplinkLUID")
			require.Equal(t, tc.wantForwarding, state.forwardingEnabled, "forwardingEnabled")
		})
	}
}

// winNATUnavailable must recognize WBEM_E_INVALID_CLASS by HRESULT alone:
// the surrounding message is localized (the sample below is from a Russian
// Windows 11 Home), so text matching is not an option.
func TestWinNATUnavailable(t *testing.T) {
	realError := errors.New(`powershell "Get-NetNat | Select-Object Name,InternalIPInterfaceAddressPrefix | ConvertTo-Json -Compress": exit status 1 (output: Get-NetNat : Недопустимый класс
At line:1 char:1
+ Get-NetNat | Select-Object Name,InternalIPInterfaceAddressPrefix | Co ...
+ ~~~~~~~~~~
    + CategoryInfo          : MetadataError: (MSFT_NetNat:root/StandardCimv2/MSFT_NetNat) [Get-NetNat], CimException
    + FullyQualifiedErrorId : HRESULT 0x80041010,Get-NetNat)`)
	require.True(t, winNATUnavailable(realError))

	require.False(t, winNATUnavailable(nil))
	require.False(t, winNATUnavailable(errors.New(`powershell "New-NetNat": exit status 1 (output: some other failure)`)))
}

// PowerShell's ConvertTo-Json emits three shapes depending on result count:
// nothing at all, a bare object, or an array. parseNetNATJSON must handle all.
func TestParseNetNATJSON(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		for _, input := range []string{"", "   ", "\r\n"} {
			entries, err := parseNetNATJSON([]byte(input))
			require.NoError(t, err)
			require.Empty(t, entries)
		}
	})

	t.Run("single object", func(t *testing.T) {
		input := `{"Name":"awl-gateway","InternalIPInterfaceAddressPrefix":"10.66.0.0/16"}`
		entries, err := parseNetNATJSON([]byte(input))
		require.NoError(t, err)
		require.Equal(t, []netNATEntry{{Name: "awl-gateway", InternalIPInterfaceAddressPrefix: "10.66.0.0/16"}}, entries)
	})

	t.Run("array", func(t *testing.T) {
		input := `[{"Name":"DockerNAT","InternalIPInterfaceAddressPrefix":"172.20.0.0/16"},
			{"Name":"awl-gateway","InternalIPInterfaceAddressPrefix":"10.66.0.0/16"}]`
		entries, err := parseNetNATJSON([]byte(input))
		require.NoError(t, err)
		require.Len(t, entries, 2)

		entry, found := findNetNAT(entries, winNATName)
		require.True(t, found)
		require.Equal(t, "10.66.0.0/16", entry.InternalIPInterfaceAddressPrefix)

		_, found = findNetNAT(entries, "no-such-nat")
		require.False(t, found)
	})

	t.Run("extra fields ignored", func(t *testing.T) {
		input := `{"Name":"awl-gateway","InternalIPInterfaceAddressPrefix":"10.66.0.0/16","Active":true,"Store":"Local"}`
		entries, err := parseNetNATJSON([]byte(input))
		require.NoError(t, err)
		require.Len(t, entries, 1)
	})

	t.Run("malformed", func(t *testing.T) {
		_, err := parseNetNATJSON([]byte(`{"Name":`))
		require.Error(t, err)
		_, err = parseNetNATJSON([]byte(`[{"Name":"x"`))
		require.Error(t, err)
	})
}
