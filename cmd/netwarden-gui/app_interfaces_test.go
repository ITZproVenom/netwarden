package main

import (
	"net"
	"net/netip"
	"testing"

	"github.com/amdzy/NetWarden/internal/capture/pcapdriver"
	networkgateway "github.com/amdzy/NetWarden/internal/network/gateway"
)

func TestInterfacesForRouteOnlyIncludesDefaultRouteAdapter(t *testing.T) {
	route := networkgateway.Route{
		GatewayIP:   netip.MustParseAddr("192.168.1.1"),
		InterfaceIP: netip.MustParseAddr("192.168.1.232"),
	}
	interfaces := []pcapdriver.Interface{
		{Name: "en0", SystemName: "en0", MAC: mustHardwareAddr(t, "00:11:22:33:44:55"), Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.232/24"), netip.MustParsePrefix("fe80::1/64")}},
		{Name: "en5", SystemName: "en5", MAC: mustHardwareAddr(t, "00:11:22:33:44:66"), Prefixes: []netip.Prefix{netip.MustParsePrefix("fe80::2/64")}},
		{Name: "lo0", SystemName: "lo0", Prefixes: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
		{Name: "utun4", SystemName: "utun4", Prefixes: []netip.Prefix{netip.MustParsePrefix("fe80::3/64")}},
	}

	got := interfacesForRoute(interfaces, route)
	if len(got) != 1 || got[0].Name != "en0" {
		t.Fatalf("interfacesForRoute() = %#v, want only en0", got)
	}
}

func TestInterfacesForRouteRemovesDuplicateSystemAdapters(t *testing.T) {
	route := networkgateway.Route{GatewayIP: netip.MustParseAddr("10.0.0.1"), InterfaceIP: netip.MustParseAddr("10.0.0.2")}
	mac := mustHardwareAddr(t, "00:11:22:33:44:55")
	interfaces := []pcapdriver.Interface{
		{Name: "capture0", SystemName: "en0", MAC: mac, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")}},
		{Name: "capture1", SystemName: "en0", MAC: mac, Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")}},
	}

	if got := interfacesForRoute(interfaces, route); len(got) != 1 {
		t.Fatalf("interfacesForRoute() returned %d duplicates, want 1", len(got))
	}
}

func mustHardwareAddr(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}
