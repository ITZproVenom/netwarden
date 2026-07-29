package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestStorePersistsInterfaceAndNickname(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	store := NewStore(path)
	if _, err := store.SetInterface("en0"); err != nil {
		t.Fatal(err)
	}
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	gatewayMAC, _ := net.ParseMAC("00:00:0c:00:00:01")
	if _, err := store.SetGatewayMAC(gatewayMAC); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetNickname(mac, "Living Room TV"); err != nil {
		t.Fatal(err)
	}

	got, err := NewStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != CurrentVersion || got.Interface != "en0" || got.GatewayMAC != gatewayMAC.String() || got.Nicknames["02:00:00:00:00:01"] != "Living Room TV" {
		t.Fatalf("unexpected configuration: %#v", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows reports synthesized POSIX permission bits; access is governed
	// by the file's ACL instead of chmod-style mode bits.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("configuration permissions are too broad: %o", info.Mode().Perm())
	}
}

func TestStoreReportsCorruptConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(path).Load(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want ErrCorrupt", err)
	}
}

func TestStoreRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"version":1} {"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(path).Load(); err == nil {
		t.Fatal("expected trailing JSON error")
	}
}

func TestStoreRejectsFutureVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"version":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewStore(path).Load()
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("got %v, want ErrUnsupportedVersion", err)
	}
}

func TestStoreMigratesVersionOneConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"interface":"en0","nicknames":{"02:00:00:00:00:01":"Printer"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := NewStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if config.Version != CurrentVersion || config.Interface != "en0" || config.Nicknames["02:00:00:00:00:01"] != "Printer" {
		t.Fatalf("unexpected migrated config: %#v", config)
	}
	if config.ScanIntervalSeconds != DefaultScanIntervalSeconds || !config.PeriodicDiscovery {
		t.Fatalf("monitoring defaults were not migrated: %#v", config)
	}
}

func TestStorePersistsMonitoringSettings(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "config.json"))
	want := MonitoringSettings{ScanIntervalSeconds: 30, OfflineAfterSeconds: 120, HistoryRetentionDays: 180, AutoStart: true, PeriodicDiscovery: false}
	if _, err := store.SetMonitoringSettings(want); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.MonitoringSettings() != want {
		t.Fatalf("got %#v, want %#v", got.MonitoringSettings(), want)
	}
}

func TestStoreRejectsInvalidMonitoringSettings(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "config.json"))
	_, err := store.SetMonitoringSettings(MonitoringSettings{ScanIntervalSeconds: 1, OfflineAfterSeconds: 60, HistoryRetentionDays: 90})
	if err == nil {
		t.Fatal("expected invalid scan interval error")
	}
}

func TestSetNicknameValidatesInput(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "config.json"))
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	if _, err := store.SetNickname(mac, "  "); !errors.Is(err, ErrInvalidNickname) {
		t.Fatalf("got %v, want ErrInvalidNickname", err)
	}
}

func TestSeparateStoresDoNotLoseConcurrentUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	const count = 16
	var wait sync.WaitGroup
	errorsFound := make(chan error, count)
	for i := 0; i < count; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			mac, _ := net.ParseMAC(fmt.Sprintf("02:00:00:00:00:%02x", index))
			_, err := NewStore(path).SetNickname(mac, fmt.Sprintf("Device %d", index))
			errorsFound <- err
		}(i)
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	config, err := NewStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Nicknames) != count {
		t.Fatalf("got %d nicknames, want %d", len(config.Nicknames), count)
	}
}
