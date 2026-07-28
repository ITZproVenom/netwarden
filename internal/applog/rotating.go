package applog

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

type Options struct {
	MaximumBytes int64
	Backups      int
}

type RotatingFile struct {
	mu      sync.Mutex
	path    string
	maximum int64
	backups int
	file    *os.File
	size    int64
}

func Open(path string, options Options) (*RotatingFile, error) {
	if options.MaximumBytes <= 0 {
		options.MaximumBytes = 2 << 20
	}
	if options.Backups <= 0 {
		options.Backups = 5
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}
	result := &RotatingFile{path: path, maximum: options.MaximumBytes, backups: options.Backups}
	if err := result.open(); err != nil {
		return nil, err
	}
	return result, nil
}

func (r *RotatingFile) Write(value []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return 0, os.ErrClosed
	}
	if r.size > 0 && r.size+int64(len(value)) > r.maximum {
		if err := r.rotate(); err != nil {
			return 0, err
		}
	}
	written, err := r.file.Write(value)
	r.size += int64(written)
	return written, err
}

func (r *RotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

func (r *RotatingFile) open() error {
	file, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open application log: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure application log: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	r.file, r.size = file, info.Size()
	return nil
}

func (r *RotatingFile) rotate() error {
	if err := r.file.Close(); err != nil {
		return err
	}
	r.file = nil
	for index := r.backups; index >= 1; index-- {
		destination := fmt.Sprintf("%s.%d", r.path, index)
		_ = os.Remove(destination)
		source := r.path
		if index > 1 {
			source = fmt.Sprintf("%s.%d", r.path, index-1)
		}
		if err := os.Rename(source, destination); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("rotate application log: %w", err)
		}
	}
	return r.open()
}

var _ io.WriteCloser = (*RotatingFile)(nil)
