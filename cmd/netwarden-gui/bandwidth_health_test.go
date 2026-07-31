package main

import (
	"testing"
	"time"

	coreapp "github.com/amdzy/NetWarden/internal/app"
	"github.com/amdzy/NetWarden/internal/shaping"
)

func TestBandwidthHealthTransitionsUseRecentDeltas(t *testing.T) {
	app := NewGUIApp()
	started := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)

	clean := app.recordBandwidthHealth(started, coreapp.BandwidthHealth{})
	if clean.unhealthy || clean.queueDrops != 0 || clean.sendErrors != 0 || clean.seconds != 0 {
		t.Fatalf("initial sample = %#v", clean)
	}

	degraded := app.recordBandwidthHealth(started.Add(5*time.Second), coreapp.BandwidthHealth{
		Forwarder: shaping.ForwarderStats{QueueDrops: 7, SendErrors: 1},
	})
	if !degraded.unhealthy || degraded.queueDrops != 7 || degraded.sendErrors != 1 || degraded.seconds != 5 {
		t.Fatalf("degraded sample = %#v", degraded)
	}

	recovered := app.recordBandwidthHealth(started.Add(10*time.Second), coreapp.BandwidthHealth{
		Forwarder: shaping.ForwarderStats{QueueDrops: 7, SendErrors: 1},
	})
	if recovered.unhealthy || recovered.queueDrops != 0 || recovered.sendErrors != 0 || recovered.seconds != 5 {
		t.Fatalf("recovered sample = %#v", recovered)
	}
}

func TestCounterDeltaHandlesRuntimeReset(t *testing.T) {
	if got := counterDelta(3, 10); got != 3 {
		t.Fatalf("counter delta after reset = %d, want 3", got)
	}
}
