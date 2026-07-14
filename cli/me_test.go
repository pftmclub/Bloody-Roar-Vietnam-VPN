package cli

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anywherelan/awl/entity"
)

func TestFormatUptime(t *testing.T) {
	cases := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"seconds only", 5 * time.Second, "5s"},
		{"minutes and seconds", 25*time.Minute + 5*time.Second, "25m 5s"},
		{"hours minutes seconds", time.Hour + 25*time.Minute + 5*time.Second, "1h 25m 5s"},
		{"zero minutes kept under a day", time.Hour + 5*time.Second, "1h 0m 5s"},
		{"just under a day keeps seconds", 23*time.Hour + 59*time.Minute + 59*time.Second, "23h 59m 59s"},
		{"exactly a day drops seconds", 24 * time.Hour, "1d 0h 0m"},
		{"over a day drops seconds", 45*time.Hour + 13*time.Minute + 31*time.Second, "1d 21h 13m"},
		{"sub-second rounds down", 900 * time.Millisecond, "1s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, formatUptime(tc.d))
		})
	}
}

func TestFormatExitDetail(t *testing.T) {
	cases := []struct {
		name         string
		publicIP     string
		ping         time.Duration
		connected    bool
		throughRelay bool
		want         string
	}{
		{"full direct", "1.2.3.4", 674 * time.Millisecond, true, false, "1.2.3.4, ping 674ms, direct"},
		{"full via relay", "1.2.3.4", 405 * time.Millisecond, true, true, "1.2.3.4, ping 405ms, via relay"},
		{"no public ip", "", 100 * time.Millisecond, true, false, "ping 100ms, direct"},
		{"zero ping dropped", "1.2.3.4", 0, true, false, "1.2.3.4, direct"},
		{"disconnected drops relay", "1.2.3.4", 100 * time.Millisecond, false, false, "1.2.3.4, ping 100ms"},
		{"nothing known", "", 0, false, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, formatExitDetail(tc.publicIP, tc.ping, tc.connected, tc.throughRelay))
		})
	}
}

func TestFormatVPNStatus(t *testing.T) {
	require.Equal(t, "not working", formatVPNStatus(entity.VPNInfo{}))
	require.Equal(t, "working (awl0, 10.66.0.1/24)", formatVPNStatus(entity.VPNInfo{
		VPNInterfaceEnabled: true, InterfaceName: "awl0", IPNet: "10.66.0.1/24",
	}))
	require.Equal(t, "working (awl0)", formatVPNStatus(entity.VPNInfo{
		VPNInterfaceEnabled: true, InterfaceName: "awl0",
	}))
	require.Equal(t, "working", formatVPNStatus(entity.VPNInfo{VPNInterfaceEnabled: true}))
}

func TestFormatServiceStatus(t *testing.T) {
	require.Equal(t, "not working", formatServiceStatus(false, "127.0.0.66:53"))
	require.Equal(t, "working (127.0.0.66:53)", formatServiceStatus(true, "127.0.0.66:53"))
	require.Equal(t, "working", formatServiceStatus(true, ""))
}
