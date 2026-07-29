package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunUpdatesWailsProductVersion(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "cmd", "netwarden-gui")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "wails.json")
	if err := os.WriteFile(path, []byte(`{"name":"NetWarden","info":{"productVersion":"1.0.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := run(root, "2.1.0-beta.1"); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), `"productVersion": "2.1.0-beta.1"`) {
		t.Fatalf("updated config = %s", contents)
	}
}

func TestRunRejectsInvalidVersion(t *testing.T) {
	if err := run(t.TempDir(), "v2.1"); err == nil {
		t.Fatal("invalid version was accepted")
	}
}
