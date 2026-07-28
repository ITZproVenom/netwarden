package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func (a *GUIApp) OpenConfigurationDirectory() error {
	store, _, err := loadSettings()
	if err != nil {
		return err
	}
	return openDirectory(filepath.Dir(store.Path()))
}

func (a *GUIApp) OpenLogDirectory() error {
	store, _, err := loadSettings()
	if err != nil {
		return err
	}
	directory := filepath.Join(filepath.Dir(store.Path()), "logs")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}
	return openDirectory(directory)
}
