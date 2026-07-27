// Package config persists user-owned NetWarden configuration.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const CurrentVersion = 1

var (
	ErrUnsupportedVersion = errors.New("unsupported configuration version")
	ErrInvalidNickname    = errors.New("nickname must contain 1 to 64 characters")
)

type Config struct {
	Version   int               `json:"version"`
	Interface string            `json:"interface,omitempty"`
	Nicknames map[string]string `json:"nicknames,omitempty"`
}

func DefaultPath() (string, error) {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find user configuration directory: %w", err)
	}
	return filepath.Join(directory, "netwarden", "config.json"), nil
}

type Store struct {
	path string
	mu   sync.Mutex
}

func NewStore(path string) *Store { return &Store{path: path} }

func (s *Store) Path() string { return s.path }

func (s *Store) Load() (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *Store) SetInterface(name string) (Config, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Config{}, errors.New("interface name cannot be empty")
	}
	return s.update(func(config *Config) error {
		config.Interface = name
		return nil
	})
}

func (s *Store) SetNickname(mac net.HardwareAddr, nickname string) (Config, error) {
	nickname = strings.TrimSpace(nickname)
	if len([]rune(nickname)) < 1 || len([]rune(nickname)) > 64 {
		return Config{}, ErrInvalidNickname
	}
	key, err := normalizeMAC(mac)
	if err != nil {
		return Config{}, err
	}
	return s.update(func(config *Config) error {
		config.Nicknames[key] = nickname
		return nil
	})
}

func (s *Store) RemoveNickname(mac net.HardwareAddr) (Config, error) {
	key, err := normalizeMAC(mac)
	if err != nil {
		return Config{}, err
	}
	return s.update(func(config *Config) error {
		delete(config.Nicknames, key)
		return nil
	})
}

func (s *Store) update(change func(*Config) error) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	config, err := s.load()
	if err != nil {
		return Config{}, err
	}
	if err := change(&config); err != nil {
		return Config{}, err
	}
	if err := s.save(config); err != nil {
		return Config{}, err
	}
	return clone(config), nil
}

func (s *Store) load() (Config, error) {
	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return defaultConfig(), nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("decode configuration %q: %w", s.path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return Config{}, fmt.Errorf("decode configuration %q: %w", s.path, err)
	}
	if config.Version != CurrentVersion {
		return Config{}, fmt.Errorf("%w: got %d, support %d", ErrUnsupportedVersion, config.Version, CurrentVersion)
	}
	if config.Nicknames == nil {
		config.Nicknames = make(map[string]string)
	}
	return clone(config), nil
}

func (s *Store) save(config Config) error {
	config.Version = CurrentVersion
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create configuration directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(s.path), ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary configuration: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("protect temporary configuration: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(config); err != nil {
		temporary.Close()
		return fmt.Errorf("encode configuration: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync configuration: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close configuration: %w", err)
	}
	if err := replaceFile(temporaryPath, s.path); err != nil {
		return fmt.Errorf("replace configuration: %w", err)
	}
	return nil
}

func defaultConfig() Config {
	return Config{Version: CurrentVersion, Nicknames: make(map[string]string)}
}

func clone(config Config) Config {
	result := config
	result.Nicknames = make(map[string]string, len(config.Nicknames))
	for mac, nickname := range config.Nicknames {
		result.Nicknames[mac] = nickname
	}
	return result
}

func normalizeMAC(mac net.HardwareAddr) (string, error) {
	if len(mac) != 6 {
		return "", fmt.Errorf("expected a 6-byte MAC address, got %d bytes", len(mac))
	}
	return strings.ToLower(mac.String()), nil
}
