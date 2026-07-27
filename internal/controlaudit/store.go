// Package controlaudit persists append-only records for approved control requests.
package controlaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/app"
)

type Store struct {
	path     string
	mu       sync.Mutex
	maxBytes int64
}

type Query struct {
	Since     time.Time
	Operation app.ControlOperation
	Outcome   string
}

func NewStore(path string) *Store { return &Store{path: path, maxBytes: 10 << 20} }

func (s *Store) Record(ctx context.Context, event app.ControlAuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
	}
	if info, statErr := os.Stat(s.path); statErr == nil && info.Size() >= s.maxBytes {
		_ = os.Remove(s.path + ".1")
		if err := os.Rename(s.path, s.path+".1"); err != nil {
			return fmt.Errorf("rotate audit log: %w", err)
		}
	}
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()
	if err := json.NewEncoder(file).Encode(event); err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync audit log: %w", err)
	}
	return nil
}

func (s *Store) Query(query Query) ([]app.ControlAuditEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queryUnlocked(query)
}

func (s *Store) queryUnlocked(query Query) ([]app.ControlAuditEvent, error) {
	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	var result []app.ControlAuditEvent
	for {
		var event app.ControlAuditEvent
		err := decoder.Decode(&event)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode audit log: %w", err)
		}
		if !query.Since.IsZero() && event.At.Before(query.Since) || query.Operation != "" && event.Operation != query.Operation || query.Outcome != "" && event.Outcome != query.Outcome {
			continue
		}
		result = append(result, event)
	}
	return result, nil
}

func (s *Store) Prune(before time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	events, err := s.queryUnlocked(Query{Since: before})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".audit-*.tmp")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer os.Remove(path)
	_ = temporary.Chmod(0o600)
	encoder := json.NewEncoder(temporary)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			temporary.Close()
			return err
		}
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return replaceFile(path, s.path)
}

func (s *Store) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
