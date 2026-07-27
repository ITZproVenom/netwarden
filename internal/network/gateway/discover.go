// Package gateway discovers the operating system's default IPv4 route.
package gateway

import (
	"context"
	"fmt"
	"net/netip"

	jackpal "github.com/jackpal/gateway"
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
		return Route{}, fmt.Errorf("discover default IPv4 gateway: %w", err)
	}
	interfaceIP, err := jackpal.DiscoverInterface()
	if err != nil {
		return Route{}, fmt.Errorf("discover default IPv4 interface: %w", err)
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
