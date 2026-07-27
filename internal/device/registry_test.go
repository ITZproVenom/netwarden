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
	if changed := registry.MarkOffline(seen.Add(time.Hour), time.Minute); len(changed) != 0 {
		t.Fatalf("gateway expired: %#v", changed)
	}
}
