//go:build !windows

package controlaudit

import "os"

func replaceFile(source, destination string) error { return os.Rename(source, destination) }
