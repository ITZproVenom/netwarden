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
)

func TestStoreRoundTripsSnapshot(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "state", "history.json"))
	now := time.Now().UTC().Truncate(time.Second)
	want := Snapshot{
		Devices:   []device.Device{{IP: netip.MustParseAddr("192.168.1.20"), MAC: "02:00:00:00:00:20", FirstSeen: now, LastSeen: now, Online: true}},
		Conflicts: []defense.Conflict{{GatewayIP: netip.MustParseAddr("192.168.1.1"), ClaimedMAC: "02:00:00:00:00:99", FirstSeen: now, LastSeen: now, Count: 2, Active: true}},
	}
	if err := store.Save(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Devices) != 1 || got.Devices[0].MAC != want.Devices[0].MAC || len(got.Conflicts) != 1 || got.Conflicts[0].Count != 2 {
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
