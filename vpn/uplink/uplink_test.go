package uplink

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBest(t *testing.T) {
	tun := Route{IfLUID: 100, IfIndex: 10, Metric: 1, Up: true}
	ethernet := Route{IfLUID: 200, IfIndex: 20, Metric: 25, Up: true}
	wifi := Route{IfLUID: 300, IfIndex: 30, Metric: 50, Up: true}
	downLTE := Route{IfLUID: 400, IfIndex: 40, Metric: 5, Up: false}

	t.Run("lowest metric wins", func(t *testing.T) {
		best, ok := Best([]Route{wifi, ethernet}, 0)
		require.True(t, ok)
		require.Equal(t, ethernet, best)
	})

	t.Run("excluded TUN is skipped even with the best metric", func(t *testing.T) {
		best, ok := Best([]Route{tun, wifi, ethernet}, tun.IfLUID)
		require.True(t, ok)
		require.Equal(t, ethernet, best)
	})

	t.Run("down interfaces are skipped", func(t *testing.T) {
		best, ok := Best([]Route{downLTE, wifi}, 0)
		require.True(t, ok)
		require.Equal(t, wifi, best)
	})

	t.Run("no candidates", func(t *testing.T) {
		_, ok := Best(nil, 0)
		require.False(t, ok)

		_, ok = Best([]Route{downLTE}, 0)
		require.False(t, ok, "only-down candidates must not qualify")

		_, ok = Best([]Route{tun}, tun.IfLUID)
		require.False(t, ok, "the only default route being our TUN means no uplink")
	})

	t.Run("tie keeps first occurrence", func(t *testing.T) {
		second := Route{IfLUID: 500, IfIndex: 50, Metric: ethernet.Metric, Up: true}
		best, ok := Best([]Route{ethernet, second}, 0)
		require.True(t, ok)
		require.Equal(t, ethernet, best)
	})
}
