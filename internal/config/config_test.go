package config

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestStorePersistsInterfaceAndNickname(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "config.json")
	store := NewStore(path)
	if _, err := store.SetInterface("en0"); err != nil {
		t.Fatal(err)
	}
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	if _, err := store.SetNickname(mac, "Living Room TV"); err != nil {
		t.Fatal(err)
	}

	got, err := NewStore(path).Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != CurrentVersion || got.Interface != "en0" || got.Nicknames["02:00:00:00:00:01"] != "Living Room TV" {
		t.Fatalf("unexpected configuration: %#v", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("configuration permissions are too broad: %o", info.Mode().Perm())
	}
}

func TestStoreReportsCorruptConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(path).Load(); err == nil {
		t.Fatal("expected corrupt configuration error")
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

func TestSetNicknameValidatesInput(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "config.json"))
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	if _, err := store.SetNickname(mac, "  "); !errors.Is(err, ErrInvalidNickname) {
		t.Fatalf("got %v, want ErrInvalidNickname", err)
	}
}
