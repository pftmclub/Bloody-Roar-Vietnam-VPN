//go:build windows

package uplink

import (
	"fmt"

	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// BestDefault scans the live routing table for the given address family and
// returns the uplink candidate per Best. excludeLUID is the adapter to skip
// (our Wintun); pass 0 to exclude nothing. ok=false with err==nil means the
// scan worked but no uplink exists right now (offline host) — callers treat
// that as "index 0", not as a failure.
func BestDefault(family winipcfg.AddressFamily, excludeLUID winipcfg.LUID) (Route, bool, error) {
	rows, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		return Route{}, false, fmt.Errorf("get IP forward table: %w", err)
	}

	candidates := make([]Route, 0, 4)
	for i := range rows {
		r := &rows[i]
		if r.DestinationPrefix.PrefixLength != 0 {
			continue
		}
		// Interface rows can disappear between the table snapshot and these
		// lookups (adapter removal mid-scan) — skip candidates we cannot
		// fully qualify instead of failing the whole detection.
		ifRow, err := r.InterfaceLUID.Interface()
		if err != nil {
			continue
		}
		ipIface, err := r.InterfaceLUID.IPInterface(family)
		if err != nil {
			continue
		}
		candidates = append(candidates, Route{
			IfLUID:  uint64(r.InterfaceLUID),
			IfIndex: r.InterfaceIndex,
			Metric:  r.Metric + ipIface.Metric,
			Up:      ifRow.OperStatus == winipcfg.IfOperStatusUp,
		})
	}

	best, ok := Best(candidates, uint64(excludeLUID))
	return best, ok, nil
}
