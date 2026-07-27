package network

import (
	"errors"
	"net/netip"
	"testing"
)

func TestIPv4HostsRespectsPrefix(t *testing.T) {
	hosts, err := IPv4Hosts(netip.MustParsePrefix("192.168.20.128/30"), 256)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{
		netip.MustParseAddr("192.168.20.129"),
		netip.MustParseAddr("192.168.20.130"),
	}
	if len(hosts) != len(want) {
		t.Fatalf("got %d hosts, want %d", len(hosts), len(want))
	}
	for i := range want {
		if hosts[i] != want[i] {
			t.Fatalf("host %d = %s, want %s", i, hosts[i], want[i])
		}
	}
}

func TestIPv4HostsHandlesPointToPointPrefixes(t *testing.T) {
	hosts, err := IPv4Hosts(netip.MustParsePrefix("10.0.0.4/31"), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 || hosts[0].String() != "10.0.0.4" || hosts[1].String() != "10.0.0.5" {
		t.Fatalf("unexpected hosts: %v", hosts)
	}
}

func TestIPv4HostsRejectsOversizedSubnet(t *testing.T) {
	_, err := IPv4Hosts(netip.MustParsePrefix("10.0.0.0/8"), 4096)
	if !errors.Is(err, ErrHostLimit) {
		t.Fatalf("got %v, want ErrHostLimit", err)
	}
}

func TestIPv4HostsRejectsIPv6(t *testing.T) {
	_, err := IPv4Hosts(netip.MustParsePrefix("2001:db8::/64"), 256)
	if !errors.Is(err, ErrNotIPv4) {
		t.Fatalf("got %v, want ErrNotIPv4", err)
	}
}
