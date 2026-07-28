package applog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRotatingFileBoundsAndRetainsLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "netwarden.jsonl")
	writer, err := Open(path, Options{MaximumBytes: 8, Backups: 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"first\n", "second\n", "third\n", "fourth\n"} {
		if _, err := writer.Write([]byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, path + ".1", path + ".2"} {
		info, err := os.Stat(candidate)
		if err != nil {
			t.Fatalf("missing %s: %v", candidate, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o", candidate, info.Mode().Perm())
		}
	}
}
