package shaping

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestLimiterReservesIndependentDirectionalCapacity(t *testing.T) {
	limiter, err := NewLimiter(Policy{DownloadBitsPerSecond: 8_000, BurstBytes: 1_000})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	if delay := limiter.download.reserve(now, 1_000); delay != 0 {
		t.Fatalf("initial burst delay = %s", delay)
	}
	if delay := limiter.download.reserve(now, 1_000); delay != time.Second {
		t.Fatalf("second download delay = %s, want 1s", delay)
	}
	if delay := limiter.download.reserve(now, 1_000); delay != 2*time.Second {
		t.Fatalf("queued download delay = %s, want 2s", delay)
	}
	if delay := limiter.upload.reserve(now, 1_000); delay != 0 {
		t.Fatalf("unlimited upload delay = %s", delay)
	}
}

func TestLimiterRefillsBurstCapacity(t *testing.T) {
	limiter, err := NewLimiter(Policy{UploadBitsPerSecond: 8_000, BurstBytes: 1_000})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	_ = limiter.upload.reserve(now, 1_000)
	if delay := limiter.upload.reserve(now.Add(time.Second), 1_000); delay != 0 {
		t.Fatalf("refilled upload delay = %s", delay)
	}
}

func TestLimiterWaitHonorsCancellation(t *testing.T) {
	limiter, err := NewLimiter(Policy{DownloadBitsPerSecond: 8, BurstBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := limiter.Wait(context.Background(), Download, 1); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	started := time.Now()
	if err := limiter.Wait(ctx, Download, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context cancellation", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("limiter did not stop promptly")
	}
}

func TestManagerSetsUpdatesAndRemovesPolicies(t *testing.T) {
	manager := NewManager()
	mac, _ := net.ParseMAC("02:00:00:00:00:20")
	if err := manager.Set(mac, Policy{DownloadBitsPerSecond: 10_000_000}); err != nil {
		t.Fatal(err)
	}
	snapshot := manager.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Policy.BurstBytes != DefaultBurstBytes {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	if err := manager.Set(mac, Policy{UploadBitsPerSecond: 2_000_000, BurstBytes: 4_096}); err != nil {
		t.Fatal(err)
	}
	snapshot = manager.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Policy.UploadBitsPerSecond != 2_000_000 || snapshot[0].Policy.DownloadBitsPerSecond != 0 {
		t.Fatalf("updated snapshot: %#v", snapshot)
	}
	if err := manager.Remove(mac); err != nil {
		t.Fatal(err)
	}
	if len(manager.Snapshot()) != 0 {
		t.Fatal("policy was not removed")
	}
	if err := manager.Wait(context.Background(), mac, Download, 1_500); err != nil {
		t.Fatalf("unmanaged device should pass without delay: %v", err)
	}
}

func TestManagerSeparatesUnrestrictedTrackingFromLimits(t *testing.T) {
	manager := NewManager()
	mac, _ := net.ParseMAC("02:00:00:00:00:21")
	if err := manager.Track(mac); err != nil || !manager.Has(mac) || manager.Limited(mac) || len(manager.Snapshot()) != 0 {
		t.Fatalf("unexpected tracked state: err=%v snapshot=%#v", err, manager.Snapshot())
	}
	if err := manager.Set(mac, Policy{UploadBitsPerSecond: 1_000_000}); err != nil || !manager.Limited(mac) {
		t.Fatalf("could not upgrade tracked identity: %v", err)
	}
	if err := manager.SetUnrestricted(mac); err != nil || manager.Limited(mac) || !manager.Has(mac) {
		t.Fatalf("could not downgrade limited identity: %v", err)
	}
	if err := manager.Untrack(mac); err != nil || manager.Has(mac) {
		t.Fatalf("could not remove tracked identity: %v", err)
	}
}

func TestPolicyValidation(t *testing.T) {
	for _, policy := range []Policy{
		{},
		{DownloadBitsPerSecond: 1, BurstBytes: -1},
		{DownloadBitsPerSecond: 1, BurstBytes: MaximumBurstBytes + 1},
	} {
		if err := policy.Validate(); err == nil {
			t.Fatalf("accepted invalid policy: %#v", policy)
		}
	}
	manager := NewManager()
	if err := manager.Set(net.HardwareAddr{1, 0, 0, 0, 0, 1}, Policy{DownloadBitsPerSecond: 1}); err == nil {
		t.Fatal("accepted multicast MAC")
	}
}

func TestManagerSupportsConcurrentPolicyAccess(t *testing.T) {
	manager := NewManager()
	mac, _ := net.ParseMAC("02:00:00:00:00:30")
	if err := manager.Set(mac, Policy{DownloadBitsPerSecond: 1_000_000}); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for index := 0; index < 16; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			if index%2 == 0 {
				_ = manager.Set(mac, Policy{DownloadBitsPerSecond: uint64(1_000_000 + index)})
				return
			}
			_ = manager.Wait(context.Background(), mac, Upload, 1_500)
			_ = manager.Snapshot()
		}(index)
	}
	workers.Wait()
}
