package discovery

import (
	"context"
	"net"
	"net/netip"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/packet"
)

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
var emptyMAC = net.HardwareAddr{0, 0, 0, 0, 0, 0}

// ARPProber implements Prober by broadcasting well-formed ARP requests.
type ARPProber struct {
	driver capture.Driver
	mac    net.HardwareAddr
	ip     netip.Addr
}

func NewARPProber(driver capture.Driver, mac net.HardwareAddr, ip netip.Addr) *ARPProber {
	return &ARPProber{
		driver: driver,
		mac:    append(net.HardwareAddr(nil), mac...),
		ip:     ip,
	}
}

func (p *ARPProber) Probe(ctx context.Context, target netip.Addr) error {
	frame, err := packet.MarshalARP(broadcastMAC, p.mac, packet.ARP{
		Operation: packet.ARPOpRequest,
		SenderMAC: p.mac,
		SenderIP:  p.ip,
		TargetMAC: emptyMAC,
		TargetIP:  target,
	})
	if err != nil {
		return err
	}
	return p.driver.Send(ctx, frame)
}
