package discovery

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/packet"
)

type sendingDriver struct {
	frame []byte
}

func (d *sendingDriver) Run(context.Context, func(capture.Frame) error) error { return nil }
func (d *sendingDriver) Close() error                                         { return nil }
func (d *sendingDriver) Send(_ context.Context, frame []byte) error {
	d.frame = append([]byte(nil), frame...)
	return nil
}

func TestARPProberBuildsBroadcastRequest(t *testing.T) {
	driver := &sendingDriver{}
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	prober := NewARPProber(driver, mac, netip.MustParseAddr("192.168.1.10"))
	if err := prober.Probe(context.Background(), netip.MustParseAddr("192.168.1.20")); err != nil {
		t.Fatal(err)
	}
	message, err := packet.ParseARP(driver.frame)
	if err != nil {
		t.Fatal(err)
	}
	if message.Operation != packet.ARPOpRequest ||
		message.SenderIP.String() != "192.168.1.10" ||
		message.TargetIP.String() != "192.168.1.20" {
		t.Fatalf("unexpected ARP request: %#v", message)
	}
	if got := net.HardwareAddr(driver.frame[:6]).String(); got != "ff:ff:ff:ff:ff:ff" {
		t.Fatalf("destination MAC = %s", got)
	}
}
