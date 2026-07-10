//go:build linux && android

package netstate

// natState holds the state needed to teardown NAT rules.
type natState struct{}

// setupNAT is a no-op on Android.
// Android exit node support requires root or special system configuration.
func setupNAT(awlSubnet, tunIfName string) (*natState, error) {
	return &natState{}, nil
}

// teardownNAT is a no-op on Android.
func teardownNAT(state *natState) error {
	return nil
}
