package discovery

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type recordingProber struct {
	mu    sync.Mutex
	hosts []netip.Addr
	wait  chan struct{}
}

func (p *recordingProber) Probe(ctx context.Context, host netip.Addr) error {
	if p.wait != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.wait:
		}
	}
	p.mu.Lock()
	p.hosts = append(p.hosts, host)
	p.mu.Unlock()
	return nil
}

func TestScannerProbesUsableHostsOnly(t *testing.T) {
	prober := &recordingProber{}
	scanner := NewScanner(prober, 256, 0)
	if err := scanner.Scan(context.Background(), netip.MustParsePrefix("192.168.4.0/30")); err != nil {
		t.Fatal(err)
	}
	if len(prober.hosts) != 2 || prober.hosts[0].String() != "192.168.4.1" || prober.hosts[1].String() != "192.168.4.2" {
		t.Fatalf("unexpected probes: %v", prober.hosts)
	}
}

func TestScannerPreventsOverlappingScans(t *testing.T) {
	prober := &recordingProber{wait: make(chan struct{})}
	scanner := NewScanner(prober, 256, 0)
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		done <- scanner.Scan(ctx, netip.MustParsePrefix("192.168.4.0/30"))
	}()

	deadline := time.Now().Add(time.Second)
	for {
		scanner.mu.Lock()
		running := scanner.running
		scanner.mu.Unlock()
		if running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first scan did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if err := scanner.Scan(context.Background(), netip.MustParsePrefix("192.168.4.0/30")); !errors.Is(err, ErrScanInProgress) {
		t.Fatalf("got %v, want ErrScanInProgress", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestScannerPeriodicControl(t *testing.T) {
	scanner := NewScanner(&recordingProber{}, 2, 0)
	if !scanner.PeriodicEnabled() {
		t.Fatal("periodic scans should default to enabled")
	}
	scanner.SetPeriodicEnabled(false)
	if scanner.PeriodicEnabled() {
		t.Fatal("periodic scans remained enabled")
	}
}
