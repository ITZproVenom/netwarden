package network

import (
	"net"
	"net/netip"
	"testing"
)

func TestNewContextValidatesAndCopiesEndpoints(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	gatewayMAC, _ := net.ParseMAC("00:00:0c:00:00:01")
	context, err := NewContext("pcap0", "en0", netip.MustParsePrefix("192.168.1.10/24"),
		Endpoint{IP: netip.MustParseAddr("192.168.1.10"), MAC: localMAC},
		Endpoint{IP: netip.MustParseAddr("192.168.1.1"), MAC: gatewayMAC})
	if err != nil {
		t.Fatal(err)
	}
	localMAC[0] = 0xff
	if context.Prefix.String() != "192.168.1.0/24" || context.Local.MAC.String() != "02:00:00:00:00:10" {
		t.Fatalf("unexpected context: %#v", context)
	}
}

func TestNewContextRejectsGatewayOutsidePrefix(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	gatewayMAC, _ := net.ParseMAC("00:00:0c:00:00:01")
	_, err := NewContext("pcap0", "en0", netip.MustParsePrefix("192.168.1.0/24"),
		Endpoint{IP: netip.MustParseAddr("192.168.1.10"), MAC: localMAC},
		Endpoint{IP: netip.MustParseAddr("10.0.0.1"), MAC: gatewayMAC})
	if err == nil {
		t.Fatal("expected gateway validation error")
	}
}
