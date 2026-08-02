package history

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/defense"
	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/discovery"
	trafficmetrics "github.com/amdzy/NetWarden/internal/traffic"
)

func TestStoreRoundTripsSnapshot(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "state", "history.json"))
	now := time.Now().UTC().Truncate(time.Second)
	want := Snapshot{
		Devices:   []device.Device{{IP: netip.MustParseAddr("192.168.1.20"), MAC: "02:00:00:00:00:20", FirstSeen: now, LastSeen: now, Online: true}},
		Conflicts: []defense.Conflict{{GatewayIP: netip.MustParseAddr("192.168.1.1"), ClaimedMAC: "02:00:00:00:00:99", FirstSeen: now, LastSeen: now, Count: 2, Active: true}},
		IPv6Routers: discovery.IPv6RouterState{
			Baselines: []discovery.IPv6RouterIdentity{{RouterIP: netip.MustParseAddr("fe80::1"), MAC: "02:00:00:00:00:01"}},
			Conflicts: []discovery.IPv6RouterConflict{{RouterIP: netip.MustParseAddr("fe80::1"), ExpectedMAC: "02:00:00:00:00:01", ClaimedMAC: "02:00:00:00:00:99", FirstSeen: now, LastSeen: now, Count: 2, Active: true}},
		},
		Traffic: trafficmetrics.State{Sessions: []trafficmetrics.Session{{ID: "session-1", MAC: "02:00:00:00:00:20", StartedAt: now, EndedAt: now.Add(time.Minute), UploadBytes: 100}},
			Buckets: []trafficmetrics.Bucket{{MAC: "02:00:00:00:00:20", Granularity: "minute", Start: now, UploadBytes: 100}}},
	}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Devices) != 1 || got.Devices[0].MAC != want.Devices[0].MAC || len(got.Conflicts) != 1 || got.Conflicts[0].Count != 2 || len(got.IPv6Routers.Baselines) != 1 || len(got.IPv6Routers.Conflicts) != 1 || len(got.Traffic.Sessions) != 1 || len(got.Traffic.Buckets) != 1 {
		t.Fatalf("unexpected snapshot: %#v", got)
	}
}

func TestStoreClassifiesCorruptHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.json")
	if err := os.WriteFile(path, []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewStore(path).Load()
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt", err)
	}
}

func TestQueryAndPruneHistory(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-100 * 24 * time.Hour)
	snapshot := Snapshot{Devices: []device.Device{
		{IP: netip.MustParseAddr("192.168.1.2"), MAC: "02:00:00:00:00:02", Role: device.RoleLocal, LastSeen: old},
		{IP: netip.MustParseAddr("192.168.1.20"), MAC: "02:00:00:00:00:20", Role: device.RolePeer, LastSeen: old},
		{IP: netip.MustParseAddr("192.168.1.21"), MAC: "02:00:00:00:00:21", Role: device.RolePeer, LastSeen: now, Online: true},
	}}
	store := NewStore(filepath.Join(t.TempDir(), "history.json"))
	if err := store.Save(snapshot); err != nil {
		t.Fatal(err)
	}
	online := true
	queried, err := store.Query(Query{Since: now.Add(-time.Hour), Online: &online})
	if err != nil {
		t.Fatal(err)
	}
	if len(queried.Devices) != 1 || queried.Devices[0].MAC != "02:00:00:00:00:21" {
		t.Fatalf("unexpected query: %#v", queried.Devices)
	}
	pruned := Prune(snapshot, now.Add(-90*24*time.Hour))
	if len(pruned.Devices) != 2 {
		t.Fatalf("pruned devices: %#v", pruned.Devices)
	}
}
