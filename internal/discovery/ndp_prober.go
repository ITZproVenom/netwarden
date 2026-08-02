package discovery

import (
	"context"
	"net"
	"net/netip"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/packet"
)

// NDPProber resolves bounded IPv6 candidates through solicited-node multicast.
type NDPProber struct {
	driver capture.Driver
	mac    net.HardwareAddr
	ip     netip.Addr
}

func NewNDPProber(driver capture.Driver, mac net.HardwareAddr, ip netip.Addr) *NDPProber {
	return &NDPProber{driver: driver, mac: append(net.HardwareAddr(nil), mac...), ip: ip}
}

func (p *NDPProber) Probe(ctx context.Context, target netip.Addr) error {
	if target == p.ip {
		return nil
	}
	frame, err := packet.MarshalNeighborSolicitation(packet.NeighborSolicitation{
		SourceIP: p.ip, SourceMAC: p.mac, TargetIP: target,
	})
	if err != nil {
		return err
	}
	return p.driver.Send(ctx, frame)
}
