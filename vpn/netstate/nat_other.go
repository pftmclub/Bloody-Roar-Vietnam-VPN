//go:build !linux && !windows

package netstate

import "errors"

// natState holds the state needed to teardown NAT rules.
type natState struct{}

// setupNAT is not supported on this platform.
func setupNAT(awlSubnet, tunIfName string) (*natState, error) {
	return nil, errors.New("NAT setup not supported on this platform")
}

// teardownNAT is not supported on this platform.
func teardownNAT(state *natState) error {
	return nil
}
