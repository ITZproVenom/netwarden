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

type Session struct {
	ID            string    `json:"id"`
	MAC           string    `json:"mac"`
	StartedAt     time.Time `json:"started_at"`
	EndedAt       time.Time `json:"ended_at,omitempty"`
	UploadBytes   uint64    `json:"upload_bytes"`
	DownloadBytes uint64    `json:"download_bytes"`
}

type Bucket struct {
	MAC             string    `json:"mac"`
	Granularity     string    `json:"granularity"`
	Start           time.Time `json:"start"`
	UploadBytes     uint64    `json:"upload_bytes"`
	DownloadBytes   uint64    `json:"download_bytes"`
	PeakUploadBPS   uint64    `json:"peak_upload_bps"`
	PeakDownloadBPS uint64    `json:"peak_download_bps"`
}

type State struct {
	Sessions []Session `json:"sessions,omitempty"`
	Buckets  []Bucket  `json:"buckets,omitempty"`
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

	mu         sync.RWMutex
	previous   map[string]previousCounter
	devices    map[string]DeviceSnapshot
	active     map[string]int
	sessions   []Session
	buckets    map[string]Bucket
	changed    chan struct{}
	lastErr    error
	lastNotify time.Time
}

func NewMonitor(provider Provider, interval, retention time.Duration) *Monitor {
	if interval <= 0 {
		interval = time.Second
	}
	if retention <= 0 {
		retention = time.Hour
	}
	return &Monitor{provider: provider, interval: interval, retention: retention,
		previous: make(map[string]previousCounter), devices: make(map[string]DeviceSnapshot), active: make(map[string]int),
		buckets: make(map[string]Bucket), changed: make(chan struct{}, 1)}
}

func (m *Monitor) Changes() <-chan struct{} { return m.changed }

func (m *Monitor) StartSession(mac string, at time.Time) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	m.mu.Lock()
	if _, exists := m.active[mac]; exists {
		m.mu.Unlock()
		return
	}
	m.sessions = append(m.sessions, Session{ID: mac + "-" + at.UTC().Format("20060102T150405.000000000Z"), MAC: mac, StartedAt: at.UTC()})
	m.active[mac] = len(m.sessions) - 1
	m.devices[mac] = DeviceSnapshot{MAC: mac}
	delete(m.previous, mac)
	m.mu.Unlock()
	m.notifyChanged()
}

func (m *Monitor) StopSession(mac string, at time.Time) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	m.mu.Lock()
	index, exists := m.active[mac]
	if !exists {
		m.mu.Unlock()
		return
	}
	snapshot := m.devices[mac]
	m.sessions[index].EndedAt = at.UTC()
	m.sessions[index].UploadBytes, m.sessions[index].DownloadBytes = snapshot.UploadBytes, snapshot.DownloadBytes
	snapshot.UploadBPS, snapshot.DownloadBPS = 0, 0
	m.devices[mac] = snapshot
	delete(m.active, mac)
	delete(m.previous, mac)
	m.mu.Unlock()
	m.notifyChanged()
}

func (m *Monitor) StopAllSessions(at time.Time) {
	m.mu.RLock()
	macs := make([]string, 0, len(m.active))
	for mac := range m.active {
		macs = append(macs, mac)
	}
	m.mu.RUnlock()
	for _, mac := range macs {
		m.StopSession(mac, at)
	}
}

func (m *Monitor) State() State {
	m.mu.RLock()
	state := State{Sessions: append([]Session(nil), m.sessions...), Buckets: make([]Bucket, 0, len(m.buckets))}
	for _, bucket := range m.buckets {
		state.Buckets = append(state.Buckets, bucket)
	}
	m.mu.RUnlock()
	sort.Slice(state.Buckets, func(i, j int) bool {
		if state.Buckets[i].Start.Equal(state.Buckets[j].Start) {
			return state.Buckets[i].MAC < state.Buckets[j].MAC
		}
		return state.Buckets[i].Start.Before(state.Buckets[j].Start)
	})
	return state
}

func (m *Monitor) RestoreState(state State, now time.Time) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	m.mu.Lock()
	m.sessions = append([]Session(nil), state.Sessions...)
	for index := range m.sessions {
		if m.sessions[index].EndedAt.IsZero() {
			m.sessions[index].EndedAt = now.UTC()
		}
	}
	for _, bucket := range state.Buckets {
		if bucket.MAC != "" && !bucket.Start.IsZero() {
			m.buckets[bucketKey(bucket.MAC, bucket.Granularity, bucket.Start)] = bucket
		}
	}
	m.pruneBuckets(now.UTC())
	m.mu.Unlock()
}

func (m *Monitor) History(mac string, since time.Time, granularity string) []Bucket {
	m.mu.RLock()
	result := make([]Bucket, 0)
	for _, bucket := range m.buckets {
		if bucket.MAC == mac && bucket.Granularity == granularity && !bucket.Start.Before(since) {
			result = append(result, bucket)
		}
	}
	m.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].Start.Before(result[j].Start) })
	return result
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
		if _, active := m.active[counter.MAC]; !active {
			continue
		}
		current := m.devices[counter.MAC]
		current.MAC = counter.MAC
		previous, found := m.previous[counter.MAC]
		if found && at.After(previous.at) {
			uploadDelta := counterDelta(counter.UploadBytes, previous.upload)
			downloadDelta := counterDelta(counter.DownloadBytes, previous.download)
			seconds := at.Sub(previous.at).Seconds()
			current.UploadBPS = uint64(float64(uploadDelta) * 8 / seconds)
			current.DownloadBPS = uint64(float64(downloadDelta) * 8 / seconds)
			current.UploadBytes += uploadDelta
			current.DownloadBytes += downloadDelta
			if current.UploadBPS > current.PeakUploadBPS {
				current.PeakUploadBPS, current.PeakUploadAt = current.UploadBPS, at
			}
			if current.DownloadBPS > current.PeakDownloadBPS {
				current.PeakDownloadBPS, current.PeakDownloadAt = current.DownloadBPS, at
			}
			current.History = append(current.History, Point{At: at, UploadBytes: uploadDelta,
				DownloadBytes: downloadDelta, UploadBPS: current.UploadBPS, DownloadBPS: current.DownloadBPS})
			m.recordBuckets(counter.MAC, at, uploadDelta, downloadDelta, current.UploadBPS, current.DownloadBPS)
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
	m.pruneBuckets(at)
	m.notifyChangedLocked()
}

func counterDelta(current, previous uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}

func PruneState(state State, before time.Time) State {
	if before.IsZero() {
		return state
	}
	sessions := state.Sessions[:0]
	for _, session := range state.Sessions {
		if session.EndedAt.IsZero() || !session.EndedAt.Before(before) {
			sessions = append(sessions, session)
		}
	}
	buckets := state.Buckets[:0]
	for _, bucket := range state.Buckets {
		if !bucket.Start.Before(before) {
			buckets = append(buckets, bucket)
		}
	}
	state.Sessions, state.Buckets = sessions, buckets
	return state
}

func (m *Monitor) recordBuckets(mac string, at time.Time, upload, download, uploadBPS, downloadBPS uint64) {
	for _, spec := range []struct {
		name     string
		duration time.Duration
	}{{"minute", time.Minute}, {"hour", time.Hour}, {"day", 24 * time.Hour}} {
		start := at.Truncate(spec.duration)
		key := bucketKey(mac, spec.name, start)
		bucket := m.buckets[key]
		bucket.MAC, bucket.Granularity, bucket.Start = mac, spec.name, start
		bucket.UploadBytes += upload
		bucket.DownloadBytes += download
		if uploadBPS > bucket.PeakUploadBPS {
			bucket.PeakUploadBPS = uploadBPS
		}
		if downloadBPS > bucket.PeakDownloadBPS {
			bucket.PeakDownloadBPS = downloadBPS
		}
		m.buckets[key] = bucket
	}
}

func (m *Monitor) pruneBuckets(now time.Time) {
	for key, bucket := range m.buckets {
		retention := 730 * 24 * time.Hour
		if bucket.Granularity == "minute" {
			retention = 48 * time.Hour
		} else if bucket.Granularity == "hour" {
			retention = 90 * 24 * time.Hour
		}
		if bucket.Start.Before(now.Add(-retention)) {
			delete(m.buckets, key)
		}
	}
}

func bucketKey(mac, granularity string, start time.Time) string {
	return mac + "|" + granularity + "|" + start.UTC().Format(time.RFC3339)
}

func (m *Monitor) notifyChanged() {
	select {
	case m.changed <- struct{}{}:
	default:
	}
}
func (m *Monitor) notifyChangedLocked() {
	now := time.Now().UTC()
	if !m.lastNotify.IsZero() && now.Sub(m.lastNotify) < 30*time.Second {
		return
	}
	m.lastNotify = now
	select {
	case m.changed <- struct{}{}:
	default:
	}
}
