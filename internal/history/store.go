// Package history persists durable network observations separately from user settings.
package history

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/defense"
	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/discovery"
)

const CurrentVersion = 1

var ErrCorrupt = errors.New("history is corrupt")

type Snapshot struct {
	Version     int                       `json:"version"`
	Devices     []device.Device           `json:"devices,omitempty"`
	Conflicts   []defense.Conflict        `json:"gateway_conflicts,omitempty"`
	IPv6Routers discovery.IPv6RouterState `json:"ipv6_routers,omitempty"`
}

type Store struct {
	path string
	mu   sync.Mutex
}

type Query struct {
	Since  time.Time
	MAC    string
	Online *bool
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

func (s *Store) Query(query Query) (Snapshot, error) {
	snapshot, err := s.Load()
	if err != nil {
		return Snapshot{}, err
	}
	mac := strings.ToLower(strings.TrimSpace(query.MAC))
	devices := snapshot.Devices[:0]
	for _, current := range snapshot.Devices {
		if !query.Since.IsZero() && current.LastSeen.Before(query.Since) || mac != "" && strings.ToLower(current.MAC) != mac || query.Online != nil && current.Online != *query.Online {
			continue
		}
		devices = append(devices, current)
	}
	conflicts := snapshot.Conflicts[:0]
	for _, current := range snapshot.Conflicts {
		if !query.Since.IsZero() && current.LastSeen.Before(query.Since) || mac != "" && strings.ToLower(current.ClaimedMAC) != mac {
			continue
		}
		conflicts = append(conflicts, current)
	}
	snapshot.Devices, snapshot.Conflicts = devices, conflicts
	ipv6Conflicts := snapshot.IPv6Routers.Conflicts[:0]
	for _, current := range snapshot.IPv6Routers.Conflicts {
		if !query.Since.IsZero() && current.LastSeen.Before(query.Since) || mac != "" && strings.ToLower(current.ClaimedMAC) != mac {
			continue
		}
		ipv6Conflicts = append(ipv6Conflicts, current)
	}
	snapshot.IPv6Routers.Conflicts = ipv6Conflicts
	return snapshot, nil
}

func Prune(snapshot Snapshot, before time.Time) Snapshot {
	if before.IsZero() {
		return snapshot
	}
	devices := snapshot.Devices[:0]
	for _, current := range snapshot.Devices {
		if current.Role != device.RolePeer || !current.LastSeen.Before(before) {
			devices = append(devices, current)
		}
	}
	conflicts := snapshot.Conflicts[:0]
	for _, current := range snapshot.Conflicts {
		if !current.LastSeen.Before(before) {
			conflicts = append(conflicts, current)
		}
	}
	snapshot.Devices, snapshot.Conflicts = devices, conflicts
	ipv6Conflicts := snapshot.IPv6Routers.Conflicts[:0]
	for _, current := range snapshot.IPv6Routers.Conflicts {
		if !current.LastSeen.Before(before) {
			ipv6Conflicts = append(ipv6Conflicts, current)
		}
	}
	snapshot.IPv6Routers.Conflicts = ipv6Conflicts
	return snapshot
}

func (s *Store) Clear() error { return s.Save(Snapshot{}) }
