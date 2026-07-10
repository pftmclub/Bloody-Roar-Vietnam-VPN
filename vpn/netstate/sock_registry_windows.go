package netstate

import (
	"sync"
	"syscall"
)

// sockRegistry tracks live long-lived sockets (in practice: the handful of
// libp2p UDP sockets — one per QUIC listen address) so their interface
// binding can be re-applied when the uplink changes. Established TCP cannot
// survive an uplink change on any platform (the connection is pinned to its
// 4-tuple), so TCP sockets are intentionally NOT registered — dials die and
// re-dial through ControlFunc with the fresh index.
//
// Holding a syscall.RawConn pins the underlying netFD from garbage
// collection, so the registry must not grow unboundedly: it is bounded by
// construction (UDP listen sockets only) and additionally cleaned lazily on
// re-apply errors plus by a periodic liveness sweep — a no-op Control on a
// closed socket returns an error ("use of closed network connection"), which
// is the eviction signal.
//
// Windows-only because only the Windows marker needs re-binding;
// the logic itself is OS-agnostic and unit-tested with fake RawConns.
type sockRegistry struct {
	mu      sync.Mutex
	entries map[*registryEntry]struct{}
}

type registryEntry struct {
	network string
	address string
	conn    syscall.RawConn
}

func (r *sockRegistry) add(network, address string, conn syscall.RawConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = make(map[*registryEntry]struct{})
	}
	r.entries[&registryEntry{network: network, address: address, conn: conn}] = struct{}{}
}

func (r *sockRegistry) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

func (r *sockRegistry) snapshot() []*registryEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	entries := make([]*registryEntry, 0, len(r.entries))
	for e := range r.entries {
		entries = append(entries, e)
	}
	return entries
}

func (r *sockRegistry) remove(e *registryEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, e)
}

// forEachLive runs apply on every registered socket. A non-nil error from
// apply marks the socket dead (closed) and evicts it. Returns the number of
// evicted entries.
//
// apply must return an error only for Control-level failures (dead fd) —
// setsockopt failures on a live socket are the caller's to log, not an
// eviction signal.
func (r *sockRegistry) forEachLive(apply func(e *registryEntry) error) int {
	evicted := 0
	for _, e := range r.snapshot() {
		if err := apply(e); err != nil {
			r.remove(e)
			evicted++
		}
	}
	return evicted
}

// sweep evicts sockets whose fd is dead, detected via a no-op Control call.
// Cheap enough to run periodically: the registry holds a handful of entries.
func (r *sockRegistry) sweep() int {
	return r.forEachLive(func(e *registryEntry) error {
		return e.conn.Control(func(uintptr) {})
	})
}
