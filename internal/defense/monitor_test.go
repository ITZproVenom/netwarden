package defense

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/packet"
)

func TestMonitorReportsConflictingGatewayClaims(t *testing.T) {
	gatewayMAC, _ := net.ParseMAC("00:00:0c:00:00:01")
	claimedMAC, _ := net.ParseMAC("02:00:00:00:00:99")
	gatewayIP := netip.MustParseAddr("192.168.1.1")
	monitor := NewMonitor(gatewayIP, gatewayMAC, time.Minute)
	observedAt := time.Now().UTC()
	monitor.Observe(packet.ARP{
		Operation: packet.ARPOpReply,
		SenderIP:  gatewayIP, SenderMAC: claimedMAC,
	}, observedAt)

	select {
	case event := <-monitor.Events():
		if event.Kind != GatewayIdentityConflict || event.ExpectedMAC != gatewayMAC.String() ||
			event.ClaimedMAC != claimedMAC.String() || event.ObservedAt != observedAt {
			t.Fatalf("unexpected event: %#v", event)
		}
	default:
		t.Fatal("expected conflict event")
	}
}

func TestMonitorIgnoresVerifiedGatewayAndDebouncesDuplicates(t *testing.T) {
	gatewayMAC, _ := net.ParseMAC("00:00:0c:00:00:01")
	claimedMAC, _ := net.ParseMAC("02:00:00:00:00:99")
	gatewayIP := netip.MustParseAddr("192.168.1.1")
	monitor := NewMonitor(gatewayIP, gatewayMAC, time.Minute)
	now := time.Now().UTC()
	monitor.Observe(packet.ARP{Operation: packet.ARPOpRequest, SenderIP: gatewayIP, SenderMAC: gatewayMAC}, now)
	monitor.Observe(packet.ARP{Operation: packet.ARPOpRequest, SenderIP: gatewayIP, SenderMAC: claimedMAC}, now)
	monitor.Observe(packet.ARP{Operation: packet.ARPOpReply, SenderIP: gatewayIP, SenderMAC: claimedMAC}, now.Add(time.Second))

	if got := len(monitor.Events()); got != 1 {
		t.Fatalf("got %d events, want one debounced conflict", got)
	}
}
