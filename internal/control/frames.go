// Package control models explicitly requested device isolation and, more
// importantly, the corrective restoration needed to leave the LAN healthy.
package control

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/amdzy/NetWarden/internal/packet"
)

type Endpoint struct {
	IP  netip.Addr
	MAC net.HardwareAddr
}

// isolationFrame creates the frame used by the legacy-compatible isolation
// mechanism. It is intentionally unexported; callers must use Controller,
// which enforces authorization, target validation, and restoration state.
func isolationFrame(localMAC net.HardwareAddr, gateway, target Endpoint) ([]byte, error) {
	if err := validateEndpoint(gateway); err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}
	if err := validateEndpoint(target); err != nil {
		return nil, fmt.Errorf("target: %w", err)
	}
	return packet.MarshalARP(target.MAC, localMAC, packet.ARP{
		Operation: packet.ARPOpReply,
		SenderMAC: localMAC,
		SenderIP:  gateway.IP,
		TargetMAC: target.MAC,
		TargetIP:  target.IP,
	})
}

// restorationFrame advertises the gateway's verified address mapping back to
// the target. It is used immediately on restore and during graceful shutdown.
func restorationFrame(gateway, target Endpoint) ([]byte, error) {
	if err := validateEndpoint(gateway); err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}
	if err := validateEndpoint(target); err != nil {
		return nil, fmt.Errorf("target: %w", err)
	}
	return packet.MarshalARP(target.MAC, gateway.MAC, packet.ARP{
		Operation: packet.ARPOpReply,
		SenderMAC: gateway.MAC,
		SenderIP:  gateway.IP,
		TargetMAC: target.MAC,
		TargetIP:  target.IP,
	})
}

func validateEndpoint(endpoint Endpoint) error {
	if !endpoint.IP.IsValid() || !endpoint.IP.Is4() || endpoint.IP.IsUnspecified() || endpoint.IP.IsMulticast() {
		return fmt.Errorf("invalid IPv4 address %s", endpoint.IP)
	}
	if len(endpoint.MAC) != 6 || zeroMAC(endpoint.MAC) || endpoint.MAC[0]&1 != 0 {
		return fmt.Errorf("invalid unicast Ethernet MAC %s", endpoint.MAC)
	}
	return nil
}

func zeroMAC(mac net.HardwareAddr) bool {
	for _, octet := range mac {
		if octet != 0 {
			return false
		}
	}
	return true
}
