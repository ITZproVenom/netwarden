package control

import (
	"net"
	"net/netip"
	"testing"

	"github.com/amdzy/NetWarden/internal/packet"
)

func TestRestorationFrameCarriesVerifiedGatewayMapping(t *testing.T) {
	gateway := endpoint(t, "192.168.1.1", "00:00:0c:00:00:01")
	target := endpoint(t, "192.168.1.20", "02:00:00:00:00:20")
	frame, err := restorationFrame(gateway, target)
	if err != nil {
		t.Fatal(err)
	}
	message, err := packet.ParseARP(frame)
	if err != nil {
		t.Fatal(err)
	}
	if message.Operation != packet.ARPOpReply || message.SenderIP != gateway.IP ||
		message.SenderMAC.String() != gateway.MAC.String() || message.TargetIP != target.IP ||
		message.TargetMAC.String() != target.MAC.String() {
		t.Fatalf("unexpected restoration message: %#v", message)
	}
	if source := net.HardwareAddr(frame[6:12]); source.String() != gateway.MAC.String() {
		t.Fatalf("Ethernet source = %s, want gateway %s", source, gateway.MAC)
	}
}

func TestIsolationFrameAndRestorationFrameAreOpposites(t *testing.T) {
	local := endpoint(t, "192.168.1.10", "02:00:00:00:00:10")
	gateway := endpoint(t, "192.168.1.1", "00:00:0c:00:00:01")
	target := endpoint(t, "192.168.1.20", "02:00:00:00:00:20")
	isolate, err := isolationFrame(local.MAC, gateway, target)
	if err != nil {
		t.Fatal(err)
	}
	restore, err := restorationFrame(gateway, target)
	if err != nil {
		t.Fatal(err)
	}
	isolationMessage, _ := packet.ParseARP(isolate)
	restorationMessage, _ := packet.ParseARP(restore)
	if isolationMessage.SenderMAC.String() != local.MAC.String() {
		t.Fatalf("isolation sender = %s", isolationMessage.SenderMAC)
	}
	if restorationMessage.SenderMAC.String() != gateway.MAC.String() {
		t.Fatalf("restoration sender = %s", restorationMessage.SenderMAC)
	}
}

func endpoint(t *testing.T, ip, mac string) Endpoint {
	t.Helper()
	hardware, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatal(err)
	}
	return Endpoint{IP: netip.MustParseAddr(ip), MAC: hardware}
}
