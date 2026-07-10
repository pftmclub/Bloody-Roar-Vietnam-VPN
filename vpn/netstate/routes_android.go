//go:build linux && android

package netstate

// routeState holds the state needed to teardown gateway routes.
// On Android, routes are managed by VpnService.Builder, not from Go.
type routeState struct{}

// setupGatewayRoutes is a no-op on Android.
// Routes are configured via VpnService.Builder in the Android app:
//   - Gateway mode: builder.addRoute("0.0.0.0", 0) + builder.addRoute("::", 0)
//   - Normal mode: builder.addRoute("10.66.0.0", 24) (awl subnet only)
//
// fwmark is unused on Android — VpnService.protect() handles socket exemption.
func setupGatewayRoutes(tunIfName string, fwmark uint32) (*routeState, error) {
	return &routeState{}, nil
}

// teardownGatewayRoutes is a no-op on Android.
func teardownGatewayRoutes(state *routeState) error {
	return nil
}
