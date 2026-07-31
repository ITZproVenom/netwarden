package traffic

import (
	"context"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/shaping"
)

type sequenceProvider struct {
	values [][]shaping.DeviceTrafficStats
	index  int
}

func (p *sequenceProvider) BandwidthTraffic(context.Context) ([]shaping.DeviceTrafficStats, error) {
	value := p.values[p.index]
	if p.index < len(p.values)-1 {
		p.index++
	}
	return value, nil
}

func TestMonitorDerivesRatesPeaksAndHistory(t *testing.T) {
	provider := &sequenceProvider{values: [][]shaping.DeviceTrafficStats{
		{{MAC: "02:00:00:00:00:20", UploadBytes: 100, DownloadBytes: 200}},
		{{MAC: "02:00:00:00:00:20", UploadBytes: 1100, DownloadBytes: 2200}},
	}}
	monitor := NewMonitor(provider, time.Second, time.Hour)
	start := time.Now().UTC()
	monitor.sample(context.Background(), start)
	monitor.sample(context.Background(), start.Add(time.Second))
	snapshot, err := monitor.Snapshot()
	if err != nil || len(snapshot) != 1 || snapshot[0].UploadBPS != 8_000 || snapshot[0].DownloadBPS != 16_000 ||
		snapshot[0].PeakDownloadBPS != 16_000 || len(snapshot[0].History) != 1 {
		t.Fatalf("snapshot=%#v err=%v", snapshot, err)
	}
}

func TestMonitorHandlesCounterResetWithoutUnderflow(t *testing.T) {
	provider := &sequenceProvider{values: [][]shaping.DeviceTrafficStats{
		{{MAC: "02:00:00:00:00:20", UploadBytes: 1000}},
		{{MAC: "02:00:00:00:00:20", UploadBytes: 10}},
	}}
	monitor := NewMonitor(provider, time.Second, time.Hour)
	start := time.Now().UTC()
	monitor.sample(context.Background(), start)
	monitor.sample(context.Background(), start.Add(time.Second))
	snapshot, _ := monitor.Snapshot()
	if snapshot[0].UploadBPS != 0 || snapshot[0].History[0].UploadBytes != 0 {
		t.Fatalf("counter reset underflowed: %#v", snapshot[0])
	}
}
