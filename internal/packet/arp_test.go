package packet

import (
	"net"
	"net/netip"
	"testing"
)

func TestARPRoundTrip(t *testing.T) {
	source := mustMAC(t, "02:00:00:00:00:01")
	destination := mustMAC(t, "ff:ff:ff:ff:ff:ff")
	want := ARP{
		Operation: ARPOpRequest,
		SenderMAC: source,
		SenderIP:  netip.MustParseAddr("192.168.1.10"),
		TargetMAC: mustMAC(t, "00:00:00:00:00:00"),
		TargetIP:  netip.MustParseAddr("192.168.1.1"),
	}

	frame, err := MarshalARP(destination, source, want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseARP(frame)
	if err != nil {
		t.Fatal(err)
	}
	if got.Operation != want.Operation || got.SenderIP != want.SenderIP ||
		got.TargetIP != want.TargetIP || got.SenderMAC.String() != want.SenderMAC.String() ||
		got.TargetMAC.String() != want.TargetMAC.String() {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestParseARPRejectsShortFrame(t *testing.T) {
	if _, err := ParseARP(make([]byte, 10)); err == nil {
		t.Fatal("expected an error")
	}
}

func mustMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}
