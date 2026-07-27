//go:build !windows

package localapi

import "os"

func replaceFile(source, destination string) error { return os.Rename(source, destination) }
