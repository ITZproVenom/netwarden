// Package history persists durable network observations separately from user settings.
package history

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/amdzy/NetWarden/internal/defense"
	"github.com/amdzy/NetWarden/internal/device"
)

const CurrentVersion = 1

var ErrCorrupt = errors.New("history is corrupt")

type Snapshot struct {
	Version   int                `json:"version"`
	Devices   []device.Device    `json:"devices,omitempty"`
	Conflicts []defense.Conflict `json:"gateway_conflicts,omitempty"`
}

type Store struct {
	path string
	mu   sync.Mutex
}

func NewStore(path string) *Store { return &Store{path: path} }
func (s *Store) Path() string     { return s.path }

func (s *Store) Load() (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := lockFile(s.path + ".lock")
	if err != nil {
		return Snapshot{}, fmt.Errorf("lock history: %w", err)
	}
	defer unlock()
	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{Version: CurrentVersion}, nil
	}
	if err != nil {
		return Snapshot{}, fmt.Errorf("open history: %w", err)
	}
	defer file.Close()
	var snapshot Snapshot
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Snapshot{}, fmt.Errorf("%w: trailing data", ErrCorrupt)
	}
	if snapshot.Version != CurrentVersion {
		return Snapshot{}, fmt.Errorf("%w: unsupported version %d", ErrCorrupt, snapshot.Version)
	}
	return snapshot, nil
}

func (s *Store) Save(snapshot Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := lockFile(s.path + ".lock")
	if err != nil {
		return fmt.Errorf("lock history: %w", err)
	}
	defer unlock()
	snapshot.Version = CurrentVersion
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create history directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".history-*.tmp")
	if err != nil {
		return fmt.Errorf("create history temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(snapshot); err != nil {
		temporary.Close()
		return fmt.Errorf("encode history: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync history: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close history: %w", err)
	}
	if err := replaceFile(temporaryPath, s.path); err != nil {
		return fmt.Errorf("replace history: %w", err)
	}
	return nil
}
