package controlaudit

import (
	"context"
	"encoding/json"
	"errors"
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
