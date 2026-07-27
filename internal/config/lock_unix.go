//go:build !windows

package config

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func lockFile(path string) (func() error, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return func() error {
		return errors.Join(unix.Flock(int(file.Fd()), unix.LOCK_UN), file.Close())
	}, nil
}
