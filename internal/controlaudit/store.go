// Package controlaudit persists append-only records for approved control requests.
package controlaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/amdzy/NetWarden/internal/app"
)

type Store struct {
	path string
	mu   sync.Mutex
}

func NewStore(path string) *Store { return &Store{path: path} }

func (s *Store) Record(ctx context.Context, event app.ControlAuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
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
