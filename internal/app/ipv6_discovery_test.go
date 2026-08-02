package app

import (
	"net"
	"net/netip"
	"testing"
)

func TestIPv6DiscoverySourcePrefersLinkLocal(t *testing.T) {
	addresses := []netip.Addr{netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("fe80::10")}
	got, ok := ipv6DiscoverySource(addresses)
	if !ok || got != addresses[1] {
		t.Fatalf("source = %s, %v", got, ok)
	}
}

func TestEUI64AddressUsesLearnedPrefixAndMAC(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	got, ok := eui64Address(netip.MustParsePrefix("2001:db8:1::/64"), mac)
	want := netip.MustParseAddr("2001:db8:1:0:211:22ff:fe33:4455")
	if !ok || got != want {
		t.Fatalf("candidate = %s, %v; want %s", got, ok, want)
	}
	if _, ok := eui64Address(netip.MustParsePrefix("2001:db8::/48"), mac); ok {
		t.Fatal("derived a candidate outside a /64")
	}
}
