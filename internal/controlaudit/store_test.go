package controlaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/app"
)

func TestStoreAppendsControlAuditEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "control.jsonl")
	store := NewStore(path)
	mac, _ := net.ParseMAC("02:00:00:00:00:20")
	event := app.ControlAuditEvent{
		At: time.Now().UTC(), Operation: app.ControlDisconnect,
		Targets: []app.ControlTarget{{IP: netip.MustParseAddr("192.168.1.20"), MAC: mac}},
		Outcome: "ready_not_implemented",
	}
	if err := store.Record(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if err := store.Record(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	count := 0
	for {
		var got app.ControlAuditEvent
		err := decoder.Decode(&got)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != 2 {
		t.Fatalf("audit records = %d, want 2", count)
	}
}

func TestStoreQueriesAndPrunesAuditEvents(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "control.jsonl"))
	now := time.Now().UTC()
	for _, event := range []app.ControlAuditEvent{
		{At: now.Add(-48 * time.Hour), Operation: app.ControlDisconnect, Outcome: "old"},
		{At: now, Operation: app.ControlRestore, Outcome: "restored"},
	} {
		if err := store.Record(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	events, err := store.Query(Query{Since: now.Add(-time.Hour), Operation: app.ControlRestore})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Outcome != "restored" {
		t.Fatalf("unexpected query: %#v", events)
	}
	if err := store.Prune(now.Add(-24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	events, err = store.Query(Query{})
	if err != nil || len(events) != 1 {
		t.Fatalf("after prune: %#v, %v", events, err)
	}
}

func TestStoreQueryLimitReturnsNewestMatchingEvents(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "control.jsonl"))
	now := time.Now().UTC()
	for index := 0; index < 5; index++ {
		if err := store.Record(context.Background(), app.ControlAuditEvent{
			At: now.Add(time.Duration(index) * time.Minute), Operation: app.ControlDisconnect, Outcome: fmt.Sprintf("event-%d", index),
		}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := store.Query(Query{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Outcome != "event-3" || events[1].Outcome != "event-4" {
		t.Fatalf("limited events = %#v", events)
	}
}
