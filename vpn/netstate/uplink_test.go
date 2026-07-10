package netstate

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBestUplink(t *testing.T) {
	tun := uplinkRoute{IfLUID: 100, IfIndex: 10, Metric: 1, Up: true}
	ethernet := uplinkRoute{IfLUID: 200, IfIndex: 20, Metric: 25, Up: true}
	wifi := uplinkRoute{IfLUID: 300, IfIndex: 30, Metric: 50, Up: true}
	downLTE := uplinkRoute{IfLUID: 400, IfIndex: 40, Metric: 5, Up: false}

	t.Run("lowest metric wins", func(t *testing.T) {
		best, ok := bestUplink([]uplinkRoute{wifi, ethernet}, 0)
		require.True(t, ok)
		require.Equal(t, ethernet, best)
	})

	t.Run("excluded TUN is skipped even with the best metric", func(t *testing.T) {
		best, ok := bestUplink([]uplinkRoute{tun, wifi, ethernet}, tun.IfLUID)
		require.True(t, ok)
		require.Equal(t, ethernet, best)
	})

	t.Run("down interfaces are skipped", func(t *testing.T) {
		best, ok := bestUplink([]uplinkRoute{downLTE, wifi}, 0)
		require.True(t, ok)
		require.Equal(t, wifi, best)
	})

	t.Run("no candidates", func(t *testing.T) {
		_, ok := bestUplink(nil, 0)
		require.False(t, ok)

		_, ok = bestUplink([]uplinkRoute{downLTE}, 0)
		require.False(t, ok, "only-down candidates must not qualify")

		_, ok = bestUplink([]uplinkRoute{tun}, tun.IfLUID)
		require.False(t, ok, "the only default route being our TUN means no uplink")
	})

	t.Run("tie keeps first occurrence", func(t *testing.T) {
		second := uplinkRoute{IfLUID: 500, IfIndex: 50, Metric: ethernet.Metric, Up: true}
		best, ok := bestUplink([]uplinkRoute{ethernet, second}, 0)
		require.True(t, ok)
		require.Equal(t, ethernet, best)
	})
}
