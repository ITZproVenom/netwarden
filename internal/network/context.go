package network

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

type Endpoint struct {
	IP  netip.Addr
	MAC net.HardwareAddr
}

// Context is the immutable, validated identity of one managed IPv4 network.
type Context struct {
	CaptureName string
	SystemName  string
	Prefix      netip.Prefix
	Local       Endpoint
	Gateway     Endpoint
}

func NewContext(captureName, systemName string, prefix netip.Prefix, local, gateway Endpoint) (Context, error) {
	if captureName == "" {
		return Context{}, errors.New("capture interface name is required")
	}
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return Context{}, errors.New("a valid IPv4 prefix is required")
	}
	prefix = prefix.Masked()
	if err := validateContextEndpoint("local", local, prefix); err != nil {
		return Context{}, err
	}
	if err := validateContextEndpoint("gateway", gateway, prefix); err != nil {
		return Context{}, err
	}
	if local.IP == gateway.IP || local.MAC.String() == gateway.MAC.String() {
		return Context{}, errors.New("local and gateway endpoints must be distinct")
	}
	return Context{
		CaptureName: captureName,
		SystemName:  systemName,
		Prefix:      prefix,
		Local:       copyNetworkEndpoint(local),
		Gateway:     copyNetworkEndpoint(gateway),
	}, nil
}

func (c Context) Clone() Context {
	c.Local = copyNetworkEndpoint(c.Local)
	c.Gateway = copyNetworkEndpoint(c.Gateway)
	return c
}

func validateContextEndpoint(label string, endpoint Endpoint, prefix netip.Prefix) error {
	if !endpoint.IP.IsValid() || !endpoint.IP.Is4() || !prefix.Contains(endpoint.IP) {
		return fmt.Errorf("%s address %s is outside %s", label, endpoint.IP, prefix)
	}
	if len(endpoint.MAC) != 6 || endpoint.MAC[0]&1 != 0 {
		return fmt.Errorf("%s MAC must be a 6-byte unicast address", label)
	}
	zero := true
	for _, octet := range endpoint.MAC {
		zero = zero && octet == 0
	}
	if zero {
		return fmt.Errorf("%s MAC cannot be zero", label)
	}
	return nil
}

func copyNetworkEndpoint(endpoint Endpoint) Endpoint {
	return Endpoint{IP: endpoint.IP, MAC: append(net.HardwareAddr(nil), endpoint.MAC...)}
}
