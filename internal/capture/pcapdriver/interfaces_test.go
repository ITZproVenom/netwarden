package pcapdriver

import (
	"errors"
	"net"
	"net/netip"
	"testing"
)

func TestSelectInterfaceByCaptureOrSystemName(t *testing.T) {
	interfaces := []Interface{{
		Name: "pcap-guid", SystemName: "en0",
		MAC:      mustMAC(t, "02:00:00:00:00:01"),
		Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.20/24")},
	}}
	for _, name := range []string{"pcap-guid", "en0"} {
		got, err := SelectInterface(interfaces, name)
		if err != nil || got.Name != "pcap-guid" {
			t.Fatalf("select %q: got %#v, %v", name, got, err)
		}
	}
}

func TestSelectInterfaceRequiresChoiceWhenAmbiguous(t *testing.T) {
	interfaces := []Interface{
		{Name: "en0", MAC: mustMAC(t, "02:00:00:00:00:01"), Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.2/24")}},
		{Name: "en1", MAC: mustMAC(t, "02:00:00:00:00:02"), Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")}},
	}
	_, err := SelectInterface(interfaces, "")
	if !errors.Is(err, ErrSelectionRequired) {
		t.Fatalf("got %v, want ErrSelectionRequired", err)
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
