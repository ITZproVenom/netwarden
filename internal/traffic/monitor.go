// Package traffic derives presentation-safe bandwidth measurements from
// cumulative forwarding counters. It does not capture, redirect, or persist
// packets and is independent from UI transport concerns.
package traffic

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/shaping"
)

type Provider interface {
	BandwidthTraffic(context.Context) ([]shaping.DeviceTrafficStats, error)
}

type Point struct {
	At            time.Time
	UploadBytes   uint64
	DownloadBytes uint64
	UploadBPS     uint64
	DownloadBPS   uint64
}

type DeviceSnapshot struct {
	MAC             string
	UploadBytes     uint64
	DownloadBytes   uint64
	UploadBPS       uint64
	DownloadBPS     uint64
	PeakUploadBPS   uint64
	PeakUploadAt    time.Time
	PeakDownloadBPS uint64
	PeakDownloadAt  time.Time
	History         []Point
}

type previousCounter struct {
	at       time.Time
	upload   uint64
	download uint64
}

type Monitor struct {
	provider  Provider
	interval  time.Duration
	retention time.Duration

	mu       sync.RWMutex
	previous map[string]previousCounter
	devices  map[string]DeviceSnapshot
	lastErr  error
}

func NewMonitor(provider Provider, interval, retention time.Duration) *Monitor {
	if interval <= 0 {
		interval = time.Second
	}
	if retention <= 0 {
		retention = time.Hour
	}
	return &Monitor{provider: provider, interval: interval, retention: retention,
		previous: make(map[string]previousCounter), devices: make(map[string]DeviceSnapshot)}
}

func (m *Monitor) Run(ctx context.Context) error {
	if m.provider == nil {
		<-ctx.Done()
		return ctx.Err()
	}
	m.sample(ctx, time.Now().UTC())
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case at := <-ticker.C:
			m.sample(ctx, at.UTC())
		}
	}
}

func (m *Monitor) Snapshot() ([]DeviceSnapshot, error) {
	m.mu.RLock()
	result := make([]DeviceSnapshot, 0, len(m.devices))
	for _, current := range m.devices {
		current.History = append([]Point(nil), current.History...)
		result = append(result, current)
	}
	err := m.lastErr
	m.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].MAC < result[j].MAC })
	return result, err
}

func (m *Monitor) sample(ctx context.Context, at time.Time) {
	counters, err := m.provider.BandwidthTraffic(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastErr = err
	if err != nil {
		return
	}
	cutoff := at.Add(-m.retention)
	for _, counter := range counters {
		current := m.devices[counter.MAC]
		current.MAC, current.UploadBytes, current.DownloadBytes = counter.MAC, counter.UploadBytes, counter.DownloadBytes
		previous, found := m.previous[counter.MAC]
		if found && at.After(previous.at) {
			uploadDelta := counterDelta(counter.UploadBytes, previous.upload)
			downloadDelta := counterDelta(counter.DownloadBytes, previous.download)
			seconds := at.Sub(previous.at).Seconds()
			current.UploadBPS = uint64(float64(uploadDelta) * 8 / seconds)
			current.DownloadBPS = uint64(float64(downloadDelta) * 8 / seconds)
			if current.UploadBPS > current.PeakUploadBPS {
				current.PeakUploadBPS, current.PeakUploadAt = current.UploadBPS, at
			}
			if current.DownloadBPS > current.PeakDownloadBPS {
				current.PeakDownloadBPS, current.PeakDownloadAt = current.DownloadBPS, at
			}
			current.History = append(current.History, Point{At: at, UploadBytes: uploadDelta,
				DownloadBytes: downloadDelta, UploadBPS: current.UploadBPS, DownloadBPS: current.DownloadBPS})
		}
		first := 0
		for first < len(current.History) && current.History[first].At.Before(cutoff) {
			first++
		}
		if first > 0 {
			current.History = append([]Point(nil), current.History[first:]...)
		}
		m.previous[counter.MAC] = previousCounter{at: at, upload: counter.UploadBytes, download: counter.DownloadBytes}
		m.devices[counter.MAC] = current
	}
}

func counterDelta(current, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}
