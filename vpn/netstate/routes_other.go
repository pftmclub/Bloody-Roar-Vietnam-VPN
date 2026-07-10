//go:build !linux && !windows

package netstate

import "errors"

// routeState holds the state needed to teardown gateway routes.
type routeState struct{}

// setupGatewayRoutes is not supported on this platform.
func setupGatewayRoutes(tunIfName string, fwmark uint32) (*routeState, error) {
	return nil, errors.New("gateway routes not supported on this platform")
}

// teardownGatewayRoutes is not supported on this platform.
func teardownGatewayRoutes(state *routeState) error {
	return nil
}
