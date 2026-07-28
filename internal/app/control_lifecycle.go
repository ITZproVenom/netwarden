package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/amdzy/NetWarden/internal/control"
)

// ControlLifecycle owns active control state and cleanup. Preparing a command
// does not activate it; AdoptActive is the hand-off point for a controller on
// which the caller has already successfully applied the requested operation.
type ControlLifecycle struct {
	mu       sync.Mutex
	lease    ControlControllerLease
	targets  map[string]ControlTarget
	cancel   context.CancelFunc
	worker   chan error
	publish  func(Event)
	stopping bool
	crash    ControlCrashRecoveryPolicy
}

type ControlCrashRecoveryPolicy string

const (
	// ControlCrashRecoveryManual is explicit: an ungraceful process death cannot
	// send corrective frames, so the next process reports state for manual recovery.
	ControlCrashRecoveryManual ControlCrashRecoveryPolicy = "manual_recovery"
)

func NewControlLifecycle(publish func(Event)) *ControlLifecycle {
	return &ControlLifecycle{targets: make(map[string]ControlTarget), publish: publish, crash: ControlCrashRecoveryManual}
}

func (l *ControlLifecycle) CrashRecoveryPolicy() ControlCrashRecoveryPolicy { return l.crash }

func (l *ControlLifecycle) ContinuousRunning() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.worker != nil
}

func (l *ControlLifecycle) Prepared(request ControlRequest) {
	l.emit(EventControlPrepared, request.Operation, request.Targets, ControlStatePrepared, "")
}

func (l *ControlLifecycle) Controller() ControlController {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lease.Controller
}

func (l *ControlLifecycle) ExtendActive(operation ControlOperation, targets []ControlTarget, continuous bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lease.Controller == nil {
		return ErrControlControllerUnavailable
	}
	for _, target := range sortedUniqueTargets(targets) {
		l.targets[controlTargetKey(target)] = cloneTarget(target)
	}
	l.emitLocked(EventControlTargetStateChanged, operation, targets, ControlStateActive, "")
	if continuous && l.worker == nil {
		l.startWorkerLocked()
	}
	return nil
}

// AdoptActive transfers ownership of a prepared controller and its cleanup
// lease to the runtime. It intentionally does not perform network disruption.
func (l *ControlLifecycle) AdoptActive(lease ControlControllerLease, operation ControlOperation, targets []ControlTarget, continuous bool) error {
	if lease.Controller == nil {
		return ErrControlControllerUnavailable
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lease.Controller != nil {
		return errors.New("a control controller is already owned by the runtime")
	}
	l.lease = lease
	for _, target := range sortedUniqueTargets(targets) {
		l.targets[controlTargetKey(target)] = cloneTarget(target)
	}
	l.emitLocked(EventControlTargetStateChanged, operation, targets, ControlStateActive, "")
	if continuous {
		l.startWorkerLocked()
	}
	return nil
}

func (l *ControlLifecycle) startWorkerLocked() {
	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	l.worker = make(chan error, 1)
	go func(controller ControlController, done chan error) {
		err := controller.Run(ctx)
		l.workerStopped(done, err)
		done <- err
	}(l.lease.Controller, l.worker)
}

func (l *ControlLifecycle) Snapshot() []ControlTarget {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.targetsLocked()
}

func (l *ControlLifecycle) Restore(ctx context.Context, target ControlTarget, reason string) error {
	l.mu.Lock()
	controller := l.lease.Controller
	_, active := l.targets[controlTargetKey(target)]
	l.mu.Unlock()
	if controller == nil || !active {
		return nil
	}
	l.emit(EventControlRestorationStarted, ControlRestore, []ControlTarget{target}, ControlStateRestoring, reason)
	err := controller.Restore(ctx, mustControlEndpoint(target))
	state := ControlStateRestored
	if err != nil {
		state = ControlStateFailed
	} else {
		l.mu.Lock()
		delete(l.targets, controlTargetKey(target))
		shouldRelease := len(l.targets) == 0 && !l.stopping
		cancel := l.cancel
		l.mu.Unlock()
		if shouldRelease {
			if cancel != nil {
				cancel()
			}
			err = l.release()
		}
	}
	l.emit(EventControlRestorationCompleted, ControlRestore, []ControlTarget{target}, state, errorReason(reason, err))
	l.emit(EventControlTargetStateChanged, ControlRestore, []ControlTarget{target}, state, errorReason(reason, err))
	return err
}

func (l *ControlLifecycle) RestoreAll(ctx context.Context, reason string) error {
	l.mu.Lock()
	targets := l.targetsLocked()
	l.stopping = true
	l.mu.Unlock()
	if len(targets) == 0 {
		return l.release()
	}
	l.emit(EventControlRestorationStarted, ControlRestoreAll, targets, ControlStateRestoring, reason)
	var failures []error
	for _, target := range targets {
		if err := l.Restore(ctx, target, reason); err != nil {
			failures = append(failures, err)
		}
	}
	l.mu.Lock()
	if l.cancel != nil {
		l.cancel()
	}
	l.mu.Unlock()
	err := errors.Join(failures...)
	state := ControlStateRestored
	if err != nil {
		state = ControlStateFailed
	}
	l.emit(EventControlRestorationCompleted, ControlRestoreAll, targets, state, errorReason(reason, err))
	return errors.Join(err, l.release())
}

func (l *ControlLifecycle) Rollback(ctx context.Context, targets []ControlTarget, cause error) error {
	reason := errorReason("bulk operation failed", cause)
	l.emit(EventControlBulkRollbackStarted, ControlDisconnectAll, targets, ControlStateRestoring, reason)
	var failures []error
	for _, target := range targets {
		if err := l.Restore(ctx, target, reason); err != nil {
			failures = append(failures, err)
		}
	}
	err := errors.Join(failures...)
	state := ControlStateRestored
	if err != nil {
		state = ControlStateFailed
	}
	l.emit(EventControlBulkRollbackCompleted, ControlDisconnectAll, targets, state, errorReason(reason, err))
	return err
}

func (l *ControlLifecycle) release() error {
	l.mu.Lock()
	lease, worker := l.lease, l.worker
	l.lease, l.cancel, l.worker = ControlControllerLease{}, nil, nil
	l.stopping = false
	l.mu.Unlock()
	if worker != nil {
		<-worker
	}
	if lease.Close != nil {
		return lease.Close()
	}
	return nil
}

func (l *ControlLifecycle) workerStopped(done chan error, err error) {
	l.mu.Lock()
	stopping := l.stopping
	targets := l.targetsLocked()
	var closeLease func() error
	if !stopping && l.worker == done {
		clear(l.targets)
		closeLease = l.lease.Close
		l.lease, l.cancel, l.worker = ControlControllerLease{}, nil, nil
	}
	l.mu.Unlock()
	state := ControlStateRestored
	if err != nil && !errors.Is(err, context.Canceled) {
		state = ControlStateFailed
	}
	l.emit(EventControlContinuousWorkerStopped, ControlStopContinuous, targets, state, errorReason("worker stopped", err))
	if !stopping {
		l.emit(EventControlTargetStateChanged, ControlStopContinuous, targets, state, errorReason("worker stopped", err))
		if closeLease != nil {
			_ = closeLease()
		}
	}
}

func (l *ControlLifecycle) targetsLocked() []ControlTarget {
	targets := make([]ControlTarget, 0, len(l.targets))
	for _, target := range l.targets {
		targets = append(targets, cloneTarget(target))
	}
	sort.Slice(targets, func(i, j int) bool { return controlTargetKey(targets[i]) < controlTargetKey(targets[j]) })
	return targets
}

func (l *ControlLifecycle) emit(kind EventKind, operation ControlOperation, targets []ControlTarget, state ControlState, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.emitLocked(kind, operation, targets, state, reason)
}

func (l *ControlLifecycle) emitLocked(kind EventKind, operation ControlOperation, targets []ControlTarget, state ControlState, reason string) {
	if l.publish != nil {
		l.publish(Event{Kind: kind, Control: &ControlEvent{Operation: operation, Targets: cloneTargets(targets), State: state, Reason: reason}})
	}
}

func controlTargetKey(target ControlTarget) string { return strings.ToLower(target.MAC.String()) }

func mustControlEndpoint(target ControlTarget) control.Endpoint {
	endpoint, err := controlEndpoint(target)
	if err != nil {
		panic(fmt.Sprintf("invalid lifecycle target: %v", err))
	}
	return endpoint
}

func errorReason(reason string, err error) string {
	if err == nil {
		return reason
	}
	if reason == "" {
		return err.Error()
	}
	return reason + ": " + err.Error()
}
