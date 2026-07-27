// Package gateway discovers the operating system's default IPv4 route.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	jackpal "github.com/jackpal/gateway"
)

var (
	ErrNoDefaultRoute = errors.New("no default IPv4 route")
	ErrRouteQuery     = errors.New("default route query failed")
)

type Route struct {
	GatewayIP   netip.Addr
	InterfaceIP netip.Addr
}

type Discoverer interface {
	Discover(context.Context) (Route, error)
}

type SystemDiscoverer struct{}

func (SystemDiscoverer) Discover(ctx context.Context) (Route, error) {
	if err := ctx.Err(); err != nil {
		return Route{}, err
	}
	gatewayIP, err := jackpal.DiscoverGateway()
	if err != nil {
		var noGateway *jackpal.ErrNoGateway
		if errors.As(err, &noGateway) {
			return Route{}, fmt.Errorf("%w: %v", ErrNoDefaultRoute, err)
		}
		return Route{}, fmt.Errorf("%w: discover default IPv4 gateway: %v", ErrRouteQuery, err)
	}
	interfaceIP, err := jackpal.DiscoverInterface()
	if err != nil {
		return Route{}, fmt.Errorf("%w: discover default IPv4 interface: %v", ErrRouteQuery, err)
	}
	if err := ctx.Err(); err != nil {
		return Route{}, err
	}
	gatewayAddress, ok := netip.AddrFromSlice(gatewayIP)
	if !ok || !gatewayAddress.Unmap().Is4() {
		return Route{}, fmt.Errorf("default gateway returned invalid IPv4 address %q", gatewayIP)
	}
	interfaceAddress, ok := netip.AddrFromSlice(interfaceIP)
	if !ok || !interfaceAddress.Unmap().Is4() {
		return Route{}, fmt.Errorf("default interface returned invalid IPv4 address %q", interfaceIP)
	}
	return Route{GatewayIP: gatewayAddress.Unmap(), InterfaceIP: interfaceAddress.Unmap()}, nil
}
