package app

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/amdzy/NetWarden/internal/control"
)

type lifecycleController struct {
	mu       sync.Mutex
	restored []control.Endpoint
	run      chan struct{}
}

func (c *lifecycleController) Restore(_ context.Context, target control.Endpoint) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.restored = append(c.restored, target)
	return nil
}

func (c *lifecycleController) Run(ctx context.Context) error {
	close(c.run)
	<-ctx.Done()
	return ctx.Err()
}

func TestControlLifecycleOwnsRestorationAndLease(t *testing.T) {
	target := testControlTarget(t)
	controller := &lifecycleController{run: make(chan struct{})}
	closed := 0
	var events []Event
	lifecycle := NewControlLifecycle(func(event Event) { events = append(events, event) })
	lifecycle.Prepared(ControlRequest{Operation: ControlContinuous, Targets: []ControlTarget{target}})
	if err := lifecycle.AdoptActive(ControlControllerLease{
		Controller: controller,
		Close:      func() error { closed++; return nil },
	}, ControlContinuous, []ControlTarget{target}, true); err != nil {
		t.Fatal(err)
	}
	<-controller.run
	if got := lifecycle.Snapshot(); len(got) != 1 {
		t.Fatalf("active targets = %d, want 1", len(got))
	}
	if err := lifecycle.RestoreAll(context.Background(), "network changed"); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(controller.restored) != 1 || len(lifecycle.Snapshot()) != 0 || closed != 1 {
		t.Fatalf("restored=%d active=%d closed=%d", len(controller.restored), len(lifecycle.Snapshot()), closed)
	}
	wanted := map[EventKind]bool{
		EventControlPrepared:                false,
		EventControlTargetStateChanged:      false,
		EventControlRestorationStarted:      false,
		EventControlRestorationCompleted:    false,
		EventControlContinuousWorkerStopped: false,
	}
	for _, event := range events {
		if _, ok := wanted[event.Kind]; ok {
			wanted[event.Kind] = true
		}
	}
	for kind, found := range wanted {
		if !found {
			t.Errorf("missing lifecycle event %v", kind)
		}
	}
}

func TestControlLifecycleReportsBulkRollback(t *testing.T) {
	target := testControlTarget(t)
	controller := &lifecycleController{run: make(chan struct{})}
	var kinds []EventKind
	lifecycle := NewControlLifecycle(func(event Event) { kinds = append(kinds, event.Kind) })
	if err := lifecycle.AdoptActive(ControlControllerLease{Controller: controller}, ControlDisconnectAll, []ControlTarget{target}, false); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Rollback(context.Background(), []ControlTarget{target}, errors.New("second target failed")); err != nil {
		t.Fatal(err)
	}
	if !containsEventKind(kinds, EventControlBulkRollbackStarted) || !containsEventKind(kinds, EventControlBulkRollbackCompleted) {
		t.Fatalf("rollback events = %v", kinds)
	}
}

func containsEventKind(kinds []EventKind, wanted EventKind) bool {
	for _, kind := range kinds {
		if kind == wanted {
			return true
		}
	}
	return false
}
