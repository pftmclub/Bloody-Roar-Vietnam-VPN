package netstate

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeRawConn implements syscall.RawConn. closed=true models a socket whose
// fd is dead: Control returns an error, which is the registry's eviction
// signal (mirrors net.ErrClosed behaviour of the real netFD).
type fakeRawConn struct {
	closed   bool
	controls int
}

func (c *fakeRawConn) Control(f func(fd uintptr)) error {
	c.controls++
	if c.closed {
		return errors.New("use of closed network connection")
	}
	f(0)
	return nil
}

func (c *fakeRawConn) Read(f func(fd uintptr) (done bool)) error {
	return errors.New("not implemented")
}
func (c *fakeRawConn) Write(f func(fd uintptr) (done bool)) error {
	return errors.New("not implemented")
}

func TestSockRegistryForEachLive(t *testing.T) {
	r := &sockRegistry{}

	live1 := &fakeRawConn{}
	live2 := &fakeRawConn{}
	dead := &fakeRawConn{closed: true}
	r.add("udp4", "0.0.0.0:6150", live1)
	r.add("udp6", "[::]:6150", live2)
	r.add("udp4", "0.0.0.0:6151", dead)
	require.Equal(t, 3, r.size())

	// Re-apply visits every entry; the one whose apply reports a dead fd is
	// evicted, the others stay.
	visited := 0
	evicted := r.forEachLive(func(e *registryEntry) error {
		visited++
		return e.conn.Control(func(uintptr) {})
	})
	require.Equal(t, 3, visited)
	require.Equal(t, 1, evicted)
	require.Equal(t, 2, r.size())

	// The dead entry is gone: a second pass does not see it.
	visited = 0
	evicted = r.forEachLive(func(e *registryEntry) error {
		visited++
		return e.conn.Control(func(uintptr) {})
	})
	require.Equal(t, 2, visited)
	require.Equal(t, 0, evicted)
}

func TestSockRegistrySweep(t *testing.T) {
	r := &sockRegistry{}
	require.Equal(t, 0, r.sweep(), "sweep on empty registry is a no-op")

	live := &fakeRawConn{}
	dead1 := &fakeRawConn{closed: true}
	dead2 := &fakeRawConn{closed: true}
	r.add("udp4", "0.0.0.0:1", live)
	r.add("udp4", "0.0.0.0:2", dead1)
	r.add("udp6", "[::]:3", dead2)

	require.Equal(t, 2, r.sweep())
	require.Equal(t, 1, r.size())

	// Sweep uses a no-op Control as the liveness probe — the surviving
	// socket must have been probed, not just skipped.
	require.NotZero(t, live.controls)

	// A socket closed later is caught by the next sweep.
	live.closed = true
	require.Equal(t, 1, r.sweep())
	require.Equal(t, 0, r.size())
}

// TestSockRegistryEntryMetadata pins that re-apply gets the original
// network/address back — the Windows marker derives the option families from
// them on every re-bind.
func TestSockRegistryEntryMetadata(t *testing.T) {
	r := &sockRegistry{}
	conn := &fakeRawConn{}
	r.add("udp6", "[::]:6150", conn)

	entries := r.snapshot()
	require.Len(t, entries, 1)
	require.Equal(t, "udp6", entries[0].network)
	require.Equal(t, "[::]:6150", entries[0].address)
	require.Same(t, conn, entries[0].conn.(*fakeRawConn))
}
