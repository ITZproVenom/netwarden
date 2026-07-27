package app

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/defense"
	"github.com/amdzy/NetWarden/internal/device"
)

type RuntimeFactory func(context.Context) (*Runtime, error)

// Supervisor rebuilds one-shot runtimes after a network-route change while
// preserving a stable event stream for a TUI, GUI, or CLI consumer.
type Supervisor struct {
	factory RuntimeFactory
	delay   time.Duration
	events  chan Event

	mu      sync.RWMutex
	current *Runtime
}

func NewSupervisor(factory RuntimeFactory, retryDelay time.Duration) *Supervisor {
	if retryDelay <= 0 {
		retryDelay = time.Second
	}
	return &Supervisor{factory: factory, delay: retryDelay, events: make(chan Event, 256)}
}

func (s *Supervisor) Events() <-chan Event { return s.events }

func (s *Supervisor) Run(ctx context.Context) error {
	if s.factory == nil {
		return errors.New("runtime factory is required")
	}
	rebuilding := false
	for {
		runtime, err := s.factory(ctx)
		if err != nil {
			if !rebuilding {
				return err
			}
			s.publish(Event{Kind: EventRuntimeRebuilding, Err: err})
			if err := waitForRetry(ctx, s.delay); err != nil {
				return err
			}
			continue
		}
		s.mu.Lock()
		s.current = runtime
		s.mu.Unlock()
		forwardCtx, stopForward := context.WithCancel(ctx)
		forwarded := make(chan struct{})
		go func() {
			defer close(forwarded)
			for {
				select {
				case <-forwardCtx.Done():
					return
				case event := <-runtime.Events():
					select {
					case s.events <- event:
					case <-forwardCtx.Done():
						return
					}
				}
			}
		}()
		err = runtime.Run(ctx)
		stopForward()
		<-forwarded
		s.mu.Lock()
		if s.current == runtime {
			s.current = nil
		}
		s.mu.Unlock()
		if !shouldRebuild(err) {
			return err
		}
		rebuilding = true
		s.publish(Event{Kind: EventRuntimeRebuilding, Err: err})
		if err := waitForRetry(ctx, s.delay); err != nil {
			return err
		}
	}
}

func shouldRebuild(err error) bool {
	if errors.Is(err, ErrNetworkChanged) {
		return true
	}
	var runtimeError *Error
	return errors.As(err, &runtimeError) && (runtimeError.Stage == StageNetworkChange || runtimeError.Stage == StageCapture)
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s *Supervisor) Current() *Runtime {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

func (s *Supervisor) Status() Status {
	if runtime := s.Current(); runtime != nil {
		return runtime.Status()
	}
	return Status{}
}

func (s *Supervisor) Devices() []device.Device {
	if runtime := s.Current(); runtime != nil {
		return runtime.Devices()
	}
	return nil
}

func (s *Supervisor) ConflictHistory() []defense.Conflict {
	if runtime := s.Current(); runtime != nil {
		return runtime.ConflictHistory()
	}
	return nil
}

func (s *Supervisor) ScanNow(ctx context.Context) error {
	if runtime := s.Current(); runtime != nil {
		return runtime.ScanNow(ctx)
	}
	return errors.New("runtime is not available")
}

func (s *Supervisor) SetPeriodicScanEnabled(enabled bool) error {
	if runtime := s.Current(); runtime != nil {
		runtime.SetPeriodicScanEnabled(enabled)
		return nil
	}
	return errors.New("runtime is not available")
}

func (s *Supervisor) publish(event Event) {
	select {
	case s.events <- event:
	default:
	}
}
