package localapi

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/app"
)

func TestServerAuthenticatesAndDispatchesRuntimeControls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	refreshes, periodic := 0, true
	server, err := Start(path, Handlers{
		Status:   func() app.Status { return app.Status{Running: true, DeviceCount: 3} },
		Refresh:  func(context.Context) error { refreshes++; return nil },
		Periodic: func(enabled bool) error { periodic = enabled; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var status app.Status
	if err := Call(ctx, path, http.MethodGet, "/status", &status); err != nil {
		t.Fatal(err)
	}
	if !status.Running || status.DeviceCount != 3 {
		t.Fatalf("unexpected status: %#v", status)
	}
	if err := Call(ctx, path, http.MethodPost, "/refresh", nil); err != nil {
		t.Fatal(err)
	}
	if err := Call(ctx, path, http.MethodPost, "/scan/pause", nil); err != nil {
		t.Fatal(err)
	}
	if refreshes != 1 || periodic {
		t.Fatalf("refreshes=%d periodic=%t", refreshes, periodic)
	}
	if err := server.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("runtime state remains: %v", err)
	}
}
