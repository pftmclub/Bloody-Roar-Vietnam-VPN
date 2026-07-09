package sockmark

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnicastIFFamilies(t *testing.T) {
	tests := []struct {
		network, address  string
		v4, v6, confident bool
	}{
		// Suffixed networks are authoritative — net.Dialer resolves the
		// address before invoking Control, so this is the common case.
		{"tcp4", "93.184.216.34:443", true, false, true},
		{"udp4", "0.0.0.0:6150", true, false, true},
		{"tcp6", "[2606:2800:220:1::]:443", false, true, true},
		{"udp6", "[::]:6150", false, true, true},

		// Bare networks fall back to the literal address.
		{"tcp", "93.184.216.34:443", true, false, true},
		{"udp", "10.66.0.2:53", true, false, true},
		{"tcp", "[2606:2800:220:1::]:443", false, true, true},
		{"udp", "[::1]:53", false, true, true},
		{"tcp", "[::ffff:1.2.3.4]:80", true, false, true}, // v4-mapped literal is a v4 destination

		// Nothing to go on: try both, best-effort.
		{"tcp", "example.com:443", true, true, false},
		{"udp", "", true, true, false},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s_%s", tc.network, tc.address), func(t *testing.T) {
			v4, v6, confident := unicastIFFamilies(tc.network, tc.address)
			require.Equal(t, tc.v4, v4, "v4")
			require.Equal(t, tc.v6, v6, "v6")
			require.Equal(t, tc.confident, confident, "confident")
		})
	}
}
