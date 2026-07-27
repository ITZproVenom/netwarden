package metadata

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/device"
)

func TestResolverAppliesNicknameAndVendor(t *testing.T) {
	resolver, err := NewResolver(map[string]string{"00:00:0c:00:00:01": "Router"})
	if err != nil {
		t.Fatal(err)
	}
	got := resolver.Enrich(device.Device{MAC: "00:00:0c:00:00:01"})
	if got.Name != "Router" || got.Vendor != "Cisco Systems, Inc" {
		t.Fatalf("unexpected metadata: %#v", got)
	}
}

func TestResolverCachesReverseDNSAndRefreshesAsynchronously(t *testing.T) {
	resolver, err := NewResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	resolver.SetHostnameLookup(func(address string) ([]string, error) {
		calls.Add(1)
		return []string{"printer.local."}, nil
	}, time.Hour)
	refreshed := make(chan string, 1)
	resolver.SetRefresh(func(mac string) { refreshed <- mac })
	snapshot := device.Device{IP: netip.MustParseAddr("192.168.1.20"), MAC: "02:00:00:00:00:20"}
	if got := resolver.Enrich(snapshot); got.Name != snapshot.IP.String() {
		t.Fatalf("initial lookup blocked or returned unexpected name: %#v", got)
	}
	select {
	case mac := <-refreshed:
		if mac != snapshot.MAC {
			t.Fatalf("refreshed %q", mac)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for hostname refresh")
	}
	if got := resolver.Enrich(snapshot); got.Name != "printer.local" {
		t.Fatalf("cached name = %q", got.Name)
	}
	if calls.Load() != 1 {
		t.Fatalf("lookup calls = %d, want 1", calls.Load())
	}
}

func TestResolverCanRemoveNicknameAtRuntime(t *testing.T) {
	resolver, err := NewResolver(map[string]string{"02:00:00:00:00:01": "Temporary"})
	if err != nil {
		t.Fatal(err)
	}
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	resolver.RemoveNickname(mac)
	got := resolver.Enrich(device.Device{IP: netip.MustParseAddr("192.168.1.20"), MAC: mac.String(), Name: "Temporary"})
	if got.Name != "192.168.1.20" {
		t.Fatalf("name = %q", got.Name)
	}
}

func TestResolverReturnsUnknownVendor(t *testing.T) {
	resolver, err := NewResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolver.Enrich(device.Device{MAC: "02:00:00:00:00:01"}); got.Vendor != "Unknown" {
		t.Fatalf("unexpected metadata: %#v", got)
	}
}
