//go:build linux && android

package netstate

// NewAndroidManager returns a Manager whose socket marker calls the
// host-supplied protect callback (VpnService.protect via the gomobile/JNI
// bridge) for each new socket. The routes/NAT sides stay no-ops on Android —
// routing is owned by the host's VpnService.Builder.
func NewAndroidManager(protect ProtectFunc) *Manager {
	return &Manager{marker: newAndroidMarker(protect)}
}
