package discovery

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/packet"
)

type ndpProbeDriver struct{ sent [][]byte }

func (d *ndpProbeDriver) Run(context.Context, func(capture.Frame) error) error { return nil }
func (d *ndpProbeDriver) Send(_ context.Context, frame []byte) error {
	d.sent = append(d.sent, append([]byte(nil), frame...))
	return nil
}
func (d *ndpProbeDriver) Close() error { return nil }

func TestNDPProberSendsValidatedSolicitationAndSkipsSelf(t *testing.T) {
	driver := &ndpProbeDriver{}
	mac, _ := net.ParseMAC("02:00:00:00:00:10")
	local, target := netip.MustParseAddr("fe80::10"), netip.MustParseAddr("fe80::20")
	prober := NewNDPProber(driver, mac, local)
	if err := prober.Probe(context.Background(), local); err != nil {
		t.Fatal(err)
	}
	if err := prober.Probe(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if len(driver.sent) != 1 {
		t.Fatalf("sent %d frames", len(driver.sent))
	}
	message, err := packet.ParseNDP(driver.sent[0])
	if err != nil || message.TargetIP != target {
		t.Fatalf("probe = %#v, %v", message, err)
	}
}
