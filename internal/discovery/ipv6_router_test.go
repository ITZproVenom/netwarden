package discovery

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/packet"
)

func TestIPv6RouterTrackerDiscoversContextAndExpiresRouter(t *testing.T) {
	local := netip.MustParseAddr("fe80::20")
	tracker := NewIPv6RouterTracker([]netip.Addr{local, netip.MustParseAddr("192.168.1.20")})
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	tracker.Observe(routerAdvertisement("fe80::1", "02:00:00:00:00:01", time.Minute), now)

	context := tracker.Snapshot(now.Add(30 * time.Second))
	if len(context.LocalAddresses) != 1 || context.DefaultRouter == nil || context.DefaultRouter.IP.String() != "fe80::1" {
		t.Fatalf("unexpected IPv6 context: %#v", context)
	}
	if expired := tracker.Snapshot(now.Add(61 * time.Second)); expired.DefaultRouter != nil {
		t.Fatalf("expired router remains selected: %#v", expired)
	}
}

func TestIPv6RouterTrackerReportsIdentityConflictAndRestoration(t *testing.T) {
	tracker := NewIPv6RouterTracker(nil)
	now := time.Now().UTC()
	tracker.Observe(routerAdvertisement("fe80::1", "02:00:00:00:00:01", time.Minute), now)
	<-tracker.Events()
	tracker.Observe(routerAdvertisement("fe80::1", "02:00:00:00:00:02", time.Minute), now.Add(time.Second))
	conflict := <-tracker.Events()
	if conflict.Kind != IPv6RouterIdentityConflict || tracker.Snapshot(now).ConflictCount != 1 {
		t.Fatalf("missing identity conflict: %#v", conflict)
	}
	tracker.Observe(routerAdvertisement("fe80::1", "02:00:00:00:00:01", time.Minute), now.Add(2*time.Second))
	restored := <-tracker.Events()
	if restored.Kind != IPv6RouterIdentityRestored || tracker.Snapshot(now).ConflictCount != 0 {
		t.Fatalf("missing identity restoration: %#v", restored)
	}
}

func TestIPv6RouterTrackerPrefersAdvertisedHighPreference(t *testing.T) {
	tracker := NewIPv6RouterTracker(nil)
	now := time.Now().UTC()
	low := routerAdvertisement("fe80::1", "02:00:00:00:00:01", time.Hour)
	low.RouterPreference = -1
	high := routerAdvertisement("fe80::2", "02:00:00:00:00:02", time.Minute)
	high.RouterPreference = 1
	tracker.Observe(low, now)
	tracker.Observe(high, now)
	if selected := tracker.Snapshot(now).DefaultRouter; selected == nil || selected.IP != high.SourceIP {
		t.Fatalf("high-preference router was not selected: %#v", selected)
	}
}

func TestIPv6RouterTrackerRoundTripsTrustAndConflictState(t *testing.T) {
	tracker := NewIPv6RouterTracker(nil)
	now := time.Now().UTC()
	tracker.Observe(routerAdvertisement("fe80::1", "02:00:00:00:00:01", time.Minute), now)
	tracker.Observe(routerAdvertisement("fe80::1", "02:00:00:00:00:99", time.Minute), now.Add(time.Second))

	restored := NewIPv6RouterTracker(nil)
	restored.RestoreState(tracker.State())
	state := restored.State()
	if len(state.Baselines) != 1 || len(state.Conflicts) != 1 || !state.Conflicts[0].Active || state.Conflicts[0].Count != 1 {
		t.Fatalf("unexpected restored state: %#v", state)
	}
}

func routerAdvertisement(ip, mac string, lifetime time.Duration) packet.NDP {
	hardware, _ := net.ParseMAC(mac)
	return packet.NDP{
		Type: packet.ICMPv6RouterAdvertisement, SourceIP: netip.MustParseAddr(ip), SourceMAC: hardware,
		RouterLifetime: lifetime,
		Prefixes: []packet.PrefixInformation{{Prefix: netip.MustParsePrefix("2001:db8:1::/64"), OnLink: true, Autonomous: true,
			ValidLifetime: time.Hour, PreferredLifetime: 30 * time.Minute}},
	}
}
