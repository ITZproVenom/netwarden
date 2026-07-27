// Package core coordinates capture and device state. It contains application
// behavior but no GUI, persistence, or platform-specific packet code.
package core

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/packet"
)

type EventKind uint8

const (
	EventObserved EventKind = iota + 1
	EventOffline
)

type Event struct {
	Kind   EventKind
	Device device.Device
}

type Service struct {
	driver        capture.Driver
	registry      *device.Registry
	offlineAfter  time.Duration
	checkInterval time.Duration
	events        chan Event

	mu      sync.Mutex
	running bool
}

func NewService(driver capture.Driver, registry *device.Registry, offlineAfter, checkInterval time.Duration) *Service {
	return &Service{
		driver: driver, registry: registry,
		offlineAfter: offlineAfter, checkInterval: checkInterval,
		events: make(chan Event, 64),
	}
}

// Events is a lossy notification stream: if a consumer falls behind, packet
// processing continues and the consumer can retrieve a fresh Snapshot.
func (s *Service) Events() <-chan Event { return s.events }

func (s *Service) Snapshot() []device.Device { return s.registry.Snapshot() }

// Run captures until cancellation or a driver error. A Service cannot be run
// more than once concurrently.
func (s *Service) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("core service is already running")
	}
	s.running = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workers sync.WaitGroup
	if s.offlineAfter > 0 && s.checkInterval > 0 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			s.runLiveness(workerCtx)
		}()
	}

	err := s.driver.Run(workerCtx, s.handleFrame)
	cancel()
	workers.Wait()
	return err
}

func (s *Service) Close() error { return s.driver.Close() }

func (s *Service) handleFrame(frame capture.Frame) error {
	message, err := packet.ParseARP(frame.Data)
	if err != nil {
		// The capture filter should normally admit only ARP, but malformed input
		// must never terminate capture.
		return nil
	}
	if message.Operation != packet.ARPOpRequest && message.Operation != packet.ARPOpReply {
		return nil
	}
	if message.SenderIP.IsUnspecified() || isZeroMAC(message.SenderMAC) {
		return nil
	}
	seenAt := frame.CapturedAt
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	snapshot, changed, err := s.registry.Observe(device.Observation{
		IP: message.SenderIP, MAC: message.SenderMAC, SeenAt: seenAt.UTC(),
	})
	if err != nil {
		return nil
	}
	if changed {
		s.publish(Event{Kind: EventObserved, Device: snapshot})
	}
	return nil
}

func (s *Service) runLiveness(ctx context.Context) {
	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			for _, snapshot := range s.registry.MarkOffline(now.UTC(), s.offlineAfter) {
				s.publish(Event{Kind: EventOffline, Device: snapshot})
			}
		}
	}
}

func (s *Service) publish(event Event) {
	select {
	case s.events <- event:
	default:
	}
}

func isZeroMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return true
	}
	for _, octet := range mac {
		if octet != 0 {
			return false
		}
	}
	return true
}
