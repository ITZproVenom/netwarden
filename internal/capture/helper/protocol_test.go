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

func TestValidateControlFrameAllowsOnlyScopedIsolationAndVerifiedRestoration(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	gatewayMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	targetMAC, _ := net.ParseMAC("02:00:00:00:00:20")
	localIP := netip.MustParseAddr("192.168.1.10")
	gatewayIP := netip.MustParseAddr("192.168.1.1")
	targetIP := netip.MustParseAddr("192.168.1.20")
	prefix := netip.MustParsePrefix("192.168.1.10/24")
	makeFrame := func(sender net.HardwareAddr) []byte {
		frame, err := packet.MarshalARP(targetMAC, sender, packet.ARP{
			Operation: packet.ARPOpReply, SenderMAC: sender, SenderIP: gatewayIP,
			TargetMAC: targetMAC, TargetIP: targetIP,
		})
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}
	if err := ValidateControlFrame(makeFrame(localMAC), localMAC, gatewayMAC, localIP, gatewayIP, prefix); err != nil {
		t.Fatalf("isolation rejected: %v", err)
	}
	if err := ValidateControlFrame(makeFrame(gatewayMAC), localMAC, gatewayMAC, localIP, gatewayIP, prefix); err != nil {
		t.Fatalf("restoration rejected: %v", err)
	}
	unknownMAC, _ := net.ParseMAC("02:00:00:00:00:99")
	if err := ValidateControlFrame(makeFrame(unknownMAC), localMAC, gatewayMAC, localIP, gatewayIP, prefix); err == nil {
		t.Fatal("accepted an unverified control sender")
	}
}
