//go:build linux

package main

import (
	"fmt"
	"os/exec"
)

func openDirectory(path string) error {
	if err := exec.Command("xdg-open", path).Start(); err != nil {
		return fmt.Errorf("open directory: %w", err)
	}
	return nil
}
