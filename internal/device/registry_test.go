package device

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRegistryUsesElapsedDurationForLiveness(t *testing.T) {
	registry := NewRegistry()
	seen := time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC)
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	_, _, err := registry.Observe(Observation{
		IP: netip.MustParseAddr("192.168.1.20"), MAC: mac, SeenAt: seen,
	})
	if err != nil {
		t.Fatal(err)
	}

	changed := registry.MarkOffline(seen.Add(61*time.Second), time.Minute)
	if len(changed) != 1 || changed[0].Online {
		t.Fatalf("expected one newly offline device, got %#v", changed)
	}
}

func TestRegistryObservationBringsDeviceOnline(t *testing.T) {
	registry := NewRegistry()
	seen := time.Now().UTC()
	mac, _ := net.ParseMAC("02:00:00:00:00:02")
	observation := Observation{IP: netip.MustParseAddr("10.0.0.2"), MAC: mac, SeenAt: seen}
	if _, _, err := registry.Observe(observation); err != nil {
		t.Fatal(err)
	}
	registry.MarkOffline(seen.Add(time.Minute), time.Minute)

	observation.SeenAt = seen.Add(2 * time.Minute)
	got, changed, err := registry.Observe(observation)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || !got.Online {
		t.Fatalf("got changed=%v device=%#v", changed, got)
	}
}

func TestRegistryDoesNotExpireGateway(t *testing.T) {
	registry := NewRegistry()
	seen := time.Now().UTC()
	mac, _ := net.ParseMAC("02:00:00:00:00:03")
	_, _, _ = registry.Observe(Observation{IP: netip.MustParseAddr("10.0.0.1"), MAC: mac, SeenAt: seen})
	if !registry.SetRole(mac, RoleGateway) {
		t.Fatal("expected role change")
	}
	if got, _ := registry.Get(mac.String()); got.Type != TypeNetwork {
		t.Fatalf("gateway type = %q", got.Type)
	}
	if changed := registry.MarkOffline(seen.Add(time.Hour), time.Minute); len(changed) != 0 {
		t.Fatalf("gateway expired: %#v", changed)
	}
}

func TestRegistryReportsMACAddressMove(t *testing.T) {
	registry := NewRegistry()
	mac, _ := net.ParseMAC("02:00:00:00:00:20")
	seen := time.Now().UTC()
	_, _, _ = registry.Observe(Observation{IP: netip.MustParseAddr("192.168.1.20"), MAC: mac, SeenAt: seen})
	result, err := registry.ObserveDetailed(Observation{IP: netip.MustParseAddr("192.168.1.21"), MAC: mac, SeenAt: seen.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) != 1 || result.Changes[0].Kind != ChangeAddressChanged ||
		result.Changes[0].PreviousIP.String() != "192.168.1.20" {
		t.Fatalf("unexpected changes: %#v", result.Changes)
	}
}

func TestRegistryGroupsIPv4AndMultipleIPv6AddressesByMAC(t *testing.T) {
	registry := NewRegistry()
	mac, _ := net.ParseMAC("02:00:00:00:00:30")
	addresses := []netip.Addr{
		netip.MustParseAddr("fe80::30"),
		netip.MustParseAddr("2001:db8::30"),
		netip.MustParseAddr("192.168.1.30"),
	}
	for index, address := range addresses {
		if _, _, err := registry.Observe(Observation{IP: address, MAC: mac, SeenAt: time.Now().Add(time.Duration(index) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	device, ok := registry.Get(mac.String())
	if !ok || device.IP != addresses[2] {
		t.Fatalf("IPv4 address was not retained as preferred: %#v", device)
	}
	if len(device.Addresses) != 3 {
		t.Fatalf("addresses = %#v", device.Addresses)
	}
}

func TestRegistryReplacesIPv4WithoutDiscardingIPv6(t *testing.T) {
	registry := NewRegistry()
	mac, _ := net.ParseMAC("02:00:00:00:00:31")
	for _, address := range []string{"192.168.1.31", "fe80::31", "192.168.1.32"} {
		if _, _, err := registry.Observe(Observation{IP: netip.MustParseAddr(address), MAC: mac}); err != nil {
			t.Fatal(err)
		}
	}
	device, _ := registry.Get(mac.String())
	if device.IP.String() != "192.168.1.32" || len(device.Addresses) != 2 {
		t.Fatalf("unexpected addresses after IPv4 replacement: %#v", device)
	}
}

func TestRegistryExpiresOnlyStaleSecondaryIPv6Addresses(t *testing.T) {
	registry := NewRegistry()
	mac, _ := net.ParseMAC("02:00:00:00:00:32")
	now := time.Now().UTC()
	for _, observation := range []Observation{
		{IP: netip.MustParseAddr("192.168.1.32"), MAC: mac, SeenAt: now},
		{IP: netip.MustParseAddr("fe80::32"), MAC: mac, SeenAt: now},
		{IP: netip.MustParseAddr("2001:db8::32"), MAC: mac, SeenAt: now.Add(2 * time.Hour)},
	} {
		if _, _, err := registry.Observe(observation); err != nil {
			t.Fatal(err)
		}
	}
	changed := registry.ExpireIPv6Addresses(now.Add(3*time.Hour), 2*time.Hour)
	if len(changed) != 1 || len(changed[0].Addresses) != 2 || containsAddress(changed[0].Addresses, netip.MustParseAddr("fe80::32")) {
		t.Fatalf("unexpected address aging result: %#v", changed)
	}
}

func TestRegistryReportsIPReassignmentAndMarksOldDeviceOffline(t *testing.T) {
	registry := NewRegistry()
	oldMAC, _ := net.ParseMAC("02:00:00:00:00:20")
	newMAC, _ := net.ParseMAC("02:00:00:00:00:21")
	ip := netip.MustParseAddr("192.168.1.20")
	_, _, _ = registry.Observe(Observation{IP: ip, MAC: oldMAC})
	result, err := registry.ObserveDetailed(Observation{IP: ip, MAC: newMAC})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) != 2 || result.Changes[0].Kind != ChangeIPConflict || result.Changes[0].Related == nil {
		t.Fatalf("unexpected changes: %#v", result.Changes)
	}
	old, ok := registry.Get(oldMAC.String())
	if !ok || old.Online {
		t.Fatalf("old owner was not marked offline: %#v", old)
	}
}

func TestRegistryKnownDevicesCanReassertConflictingIP(t *testing.T) {
	registry := NewRegistry()
	ip := netip.MustParseAddr("192.168.1.20")
	first, _ := net.ParseMAC("02:00:00:00:00:01")
	second, _ := net.ParseMAC("02:00:00:00:00:02")
	now := time.Now().UTC()
	_, _, _ = registry.Observe(Observation{IP: ip, MAC: first, SeenAt: now})
	_, _, _ = registry.Observe(Observation{IP: ip, MAC: second, SeenAt: now.Add(time.Second)})
	result, err := registry.ObserveDetailed(Observation{IP: ip, MAC: first, SeenAt: now.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	var conflict, returned bool
	for _, change := range result.Changes {
		conflict = conflict || change.Kind == ChangeIPConflict
		returned = returned || change.Kind == ChangeReturnedOnline
	}
	if !conflict || !returned {
		t.Fatalf("expected conflict and return transitions: %#v", result.Changes)
	}
	secondSnapshot, _ := registry.Get(second.String())
	if secondSnapshot.Online {
		t.Fatal("previous IP owner remained online")
	}
}

func TestRegistryRemovesStaleOfflinePeers(t *testing.T) {
	registry := NewRegistry()
	mac, _ := net.ParseMAC("02:00:00:00:00:20")
	seen := time.Now().UTC()
	_, _, _ = registry.Observe(Observation{IP: netip.MustParseAddr("192.168.1.20"), MAC: mac, SeenAt: seen})
	registry.MarkOffline(seen.Add(time.Minute), time.Minute)
	removed := registry.RemoveStale(seen.Add(2*time.Hour), time.Hour)
	if len(removed) != 1 {
		t.Fatalf("removed %#v", removed)
	}
	if _, ok := registry.Get(mac.String()); ok {
		t.Fatal("stale device remains in registry")
	}
}

func TestRegistryRestoresOnlyValidPeersOffline(t *testing.T) {
	registry := NewRegistry()
	registry.Restore([]Device{
		{IP: netip.MustParseAddr("192.168.1.20"), MAC: "02:00:00:00:00:20", Role: RolePeer, Online: true},
		{IP: netip.MustParseAddr("192.168.1.1"), MAC: "00:00:0c:00:00:01", Role: RoleGateway, Online: true},
	})
	devices := registry.Snapshot()
	if len(devices) != 1 || devices[0].Online || devices[0].Role != RolePeer {
		t.Fatalf("unexpected restored devices: %#v", devices)
	}
}
