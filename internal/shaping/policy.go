// Package shaping provides platform-independent per-device bandwidth policies.
package shaping

import (
	"errors"
	"fmt"
	"net"
)

type Direction uint8

const (
	Download Direction = iota + 1
	Upload
)

const (
	DefaultBurstBytes = 64 << 10
	MaximumBurstBytes = 64 << 20
)

// Policy uses bits per second so values map directly to the limits users and
// routers commonly display. A zero rate leaves that direction unlimited.
type Policy struct {
	DownloadBitsPerSecond uint64 `json:"downloadBitsPerSecond"`
	UploadBitsPerSecond   uint64 `json:"uploadBitsPerSecond"`
	BurstBytes            int    `json:"burstBytes"`
}

func (p Policy) Validate() error {
	if p.DownloadBitsPerSecond == 0 && p.UploadBitsPerSecond == 0 {
		return errors.New("at least one bandwidth direction must be limited")
	}
	if p.BurstBytes < 0 {
		return errors.New("burst size cannot be negative")
	}
	if p.BurstBytes > MaximumBurstBytes {
		return fmt.Errorf("burst size cannot exceed %d bytes", MaximumBurstBytes)
	}
	return nil
}

// Effective applies safe defaults used by both the limiter and status APIs.
func (p Policy) Effective() Policy {
	if p.BurstBytes == 0 {
		p.BurstBytes = DefaultBurstBytes
	}
	return p
}

func validateDirection(direction Direction) error {
	if direction != Download && direction != Upload {
		return errors.New("invalid bandwidth direction")
	}
	return nil
}

func normalizeDeviceMAC(mac net.HardwareAddr) (string, error) {
	if len(mac) != 6 {
		return "", fmt.Errorf("expected a 6-byte device MAC, got %d bytes", len(mac))
	}
	if mac[0]&1 != 0 {
		return "", errors.New("device MAC cannot be multicast")
	}
	allZero := true
	for _, value := range mac {
		allZero = allZero && value == 0
	}
	if allZero {
		return "", errors.New("device MAC cannot be empty")
	}
	return mac.String(), nil
}
