package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/packet"
)

var errAddressResolved = errors.New("ARP address resolved")

// ResolveARP asks targetIP for its MAC address and waits for the corresponding
// ARP reply. The caller controls the timeout through ctx.
func ResolveARP(ctx context.Context, driver capture.Driver, localMAC net.HardwareAddr, localIP, targetIP netip.Addr) (net.HardwareAddr, error) {
	prober := NewARPProber(driver, localMAC, localIP)
	if err := prober.Probe(ctx, targetIP); err != nil {
		return nil, fmt.Errorf("send ARP resolution request: %w", err)
	}

	var resolved net.HardwareAddr
	err := driver.Run(ctx, func(frame capture.Frame) error {
		message, err := packet.ParseARP(frame.Data)
		if err != nil || message.Operation != packet.ARPOpReply ||
			message.SenderIP != targetIP || message.TargetIP != localIP ||
			message.TargetMAC.String() != localMAC.String() || zeroHardwareAddress(message.SenderMAC) {
			return nil
		}
		resolved = append(net.HardwareAddr(nil), message.SenderMAC...)
		return errAddressResolved
	})
	if errors.Is(err, errAddressResolved) {
		return resolved, nil
	}
	if err != nil {
		return nil, fmt.Errorf("wait for ARP reply from %s: %w", targetIP, err)
	}
	return nil, fmt.Errorf("no ARP reply received from %s", targetIP)
}

func zeroHardwareAddress(address net.HardwareAddr) bool {
	if len(address) != 6 {
		return true
	}
	for _, octet := range address {
		if octet != 0 {
			return false
		}
	}
	return true
}
