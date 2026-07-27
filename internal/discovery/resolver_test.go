package discovery

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/packet"
)

type resolvingDriver struct {
	reply []byte
	sent  []byte
}

func (d *resolvingDriver) Send(_ context.Context, frame []byte) error {
	d.sent = append([]byte(nil), frame...)
	return nil
}
func (d *resolvingDriver) Run(_ context.Context, consume func(capture.Frame) error) error {
	return consume(capture.Frame{Data: d.reply})
}
func (d *resolvingDriver) Close() error { return nil }

func TestResolveARPReturnsMatchingReply(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	gatewayMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	localIP := netip.MustParseAddr("192.168.1.10")
	gatewayIP := netip.MustParseAddr("192.168.1.1")
	reply, err := packet.MarshalARP(localMAC, gatewayMAC, packet.ARP{
		Operation: packet.ARPOpReply,
		SenderMAC: gatewayMAC,
		SenderIP:  gatewayIP,
		TargetMAC: localMAC,
		TargetIP:  localIP,
	})
	if err != nil {
		t.Fatal(err)
	}
	driver := &resolvingDriver{reply: reply}
	got, err := ResolveARP(context.Background(), driver, localMAC, localIP, gatewayIP)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != gatewayMAC.String() {
		t.Fatalf("got %s, want %s", got, gatewayMAC)
	}
	request, err := packet.ParseARP(driver.sent)
	if err != nil || request.Operation != packet.ARPOpRequest || request.TargetIP != gatewayIP {
		t.Fatalf("unexpected request: %#v, %v", request, err)
	}
}
