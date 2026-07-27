package helper

import (
	"net"
	"net/netip"
	"testing"

	"github.com/amdzy/NetWarden/internal/packet"
)

func TestValidateDiscoveryFrameRestrictsSenderAndOperation(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	targetMAC, _ := net.ParseMAC("00:00:00:00:00:00")
	localIP := netip.MustParseAddr("192.168.1.10")
	prefix := netip.MustParsePrefix("192.168.1.10/24")
	frame, err := packet.MarshalARP(net.HardwareAddr{255, 255, 255, 255, 255, 255}, localMAC, packet.ARP{
		Operation: packet.ARPOpRequest, SenderMAC: localMAC, SenderIP: localIP,
		TargetMAC: targetMAC, TargetIP: netip.MustParseAddr("192.168.1.20"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateDiscoveryFrame(frame, localMAC, localIP, prefix); err != nil {
		t.Fatal(err)
	}
	frame[packet.EthernetHeaderLen+7] = byte(packet.ARPOpReply)
	if err := ValidateDiscoveryFrame(frame, localMAC, localIP, prefix); err == nil {
		t.Fatal("helper accepted an ARP reply")
	}
}
