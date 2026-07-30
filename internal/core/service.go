// Package core coordinates capture and device state. It contains application
// behavior but no GUI, persistence, or platform-specific packet code.
package core

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/packet"
)

type EventKind uint8

const (
	EventDiscovered EventKind = iota + 1
	EventReturnedOnline
	EventAddressChanged
	EventIPConflict
	EventOffline
	EventRemoved
	EventMetadataChanged
)

const EventObserved = EventDiscovered

type Event struct {
	Kind       EventKind
	Device     device.Device
	Related    *device.Device
	PreviousIP netip.Addr
}

type Enricher interface {
	Enrich(device.Device) device.Metadata
}

type ARPObserver interface {
	Observe(packet.ARP, time.Time)
}

type NDPObserver interface {
	Observe(packet.NDP, time.Time)
}

type Option func(*Service)

func WithEnricher(enricher Enricher) Option {
	return func(service *Service) { service.enricher = enricher }
}

func WithARPObserver(observer ARPObserver) Option {
	return func(service *Service) {
		if observer != nil {
			service.observers = append(service.observers, observer)
		}
	}
}

func WithNDPObserver(observer NDPObserver) Option {
	return func(service *Service) {
		if observer != nil {
			service.ndpObservers = append(service.ndpObservers, observer)
		}
	}
}

func WithRemovalAfter(retention time.Duration) Option {
	return func(service *Service) { service.removeAfter = retention }
}

func WithIgnoredSenderMAC(mac net.HardwareAddr) Option {
	return func(service *Service) {
		if len(mac) == 6 {
			service.ignoredSenderMAC = strings.ToLower(mac.String())
		}
	}
}

type Service struct {
	driver           capture.Driver
	registry         *device.Registry
	offlineAfter     time.Duration
	checkInterval    time.Duration
	removeAfter      time.Duration
	events           chan Event
	enricher         Enricher
	observers        []ARPObserver
	ndpObservers     []NDPObserver
	ignoredSenderMAC string
	dropped          atomic.Uint64

	mu      sync.Mutex
	running bool
}

func NewService(driver capture.Driver, registry *device.Registry, offlineAfter, checkInterval time.Duration, options ...Option) *Service {
	service := &Service{
		driver: driver, registry: registry,
		offlineAfter: offlineAfter, checkInterval: checkInterval,
		events: make(chan Event, 64),
	}
	for _, option := range options {
		option(service)
	}
	return service
}

// Events is a lossy notification stream: if a consumer falls behind, packet
// processing continues and the consumer can retrieve a fresh Snapshot.
func (s *Service) Events() <-chan Event { return s.events }

func (s *Service) DroppedEvents() uint64 { return s.dropped.Load() }

func (s *Service) Snapshot() []device.Device { return s.registry.Snapshot() }

func (s *Service) RefreshMetadata(mac string) bool {
	if s.enricher == nil {
		return false
	}
	snapshot, ok := s.registry.Get(mac)
	if !ok {
		return false
	}
	enriched, changed := s.registry.ApplyMetadata(mac, s.enricher.Enrich(snapshot))
	if changed {
		s.publish(Event{Kind: EventMetadataChanged, Device: enriched})
	}
	return changed
}

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
	seenAt := frame.CapturedAt
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	if err == nil {
		return s.handleARP(message, seenAt.UTC())
	}
	ndp, err := packet.ParseNDP(frame.Data)
	if err != nil {
		// Malformed and unrelated frames never terminate capture.
		return nil
	}
	for _, observer := range s.ndpObservers {
		observer.Observe(ndp, seenAt.UTC())
	}
	return s.observeAddress(ndp.SourceIP, ndp.SourceMAC, seenAt.UTC())
}

func (s *Service) handleARP(message packet.ARP, seenAt time.Time) error {
	if message.Operation != packet.ARPOpRequest && message.Operation != packet.ARPOpReply {
		return nil
	}
	if s.ignoredSenderMAC != "" && strings.EqualFold(message.SenderMAC.String(), s.ignoredSenderMAC) {
		return nil
	}
	for _, observer := range s.observers {
		observer.Observe(message, seenAt)
	}
	if message.SenderIP.IsUnspecified() || isZeroMAC(message.SenderMAC) {
		return nil
	}
	return s.observeAddress(message.SenderIP, message.SenderMAC, seenAt)
}

func (s *Service) observeAddress(ip netip.Addr, mac net.HardwareAddr, seenAt time.Time) error {
	if s.ignoredSenderMAC != "" && strings.EqualFold(mac.String(), s.ignoredSenderMAC) {
		return nil
	}
	result, err := s.registry.ObserveDetailed(device.Observation{
		IP: ip, MAC: mac, SeenAt: seenAt,
	})
	if err != nil {
		return nil
	}
	snapshot := result.Device
	if s.enricher != nil {
		if enriched, metadataChanged := s.registry.ApplyMetadata(snapshot.MAC, s.enricher.Enrich(snapshot)); metadataChanged {
			snapshot = enriched
			for i := range result.Changes {
				result.Changes[i].Device = enriched
			}
		}
	}
	for _, change := range result.Changes {
		event := Event{Device: change.Device, Related: change.Related}
		switch change.Kind {
		case device.ChangeDiscovered:
			event.Kind = EventDiscovered
		case device.ChangeReturnedOnline:
			event.Kind = EventReturnedOnline
		case device.ChangeAddressChanged, device.ChangeAddressAdded:
			event.Kind = EventAddressChanged
			event.PreviousIP = change.PreviousIP
		case device.ChangeIPConflict:
			event.Kind = EventIPConflict
		}
		s.publish(event)
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
			for _, snapshot := range s.registry.RemoveStale(now.UTC(), s.removeAfter) {
				s.publish(Event{Kind: EventRemoved, Device: snapshot})
			}
		}
	}
}

func (s *Service) publish(event Event) {
	select {
	case s.events <- event:
	default:
		s.dropped.Add(1)
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
