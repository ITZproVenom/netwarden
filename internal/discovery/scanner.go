// Package discovery coordinates network discovery without depending on a
// concrete packet capture implementation.
package discovery

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/network"
)

var ErrScanInProgress = errors.New("discovery scan already in progress")

// Prober sends a discovery probe to one IPv4 address.
type Prober interface {
	Probe(context.Context, netip.Addr) error
}

type Scanner struct {
	prober   Prober
	maxHosts int
	delay    time.Duration

	mu       sync.Mutex
	running  bool
	observer func(ScanEvent)
	periodic bool
}

type ScanEventKind uint8

const (
	ScanStarted ScanEventKind = iota + 1
	ScanCompleted
	ScanFailed
)

type ScanEvent struct {
	Kind     ScanEventKind
	Prefix   netip.Prefix
	At       time.Time
	Probed   int
	Duration time.Duration
	Err      error
}

func NewScanner(prober Prober, maxHosts int, delay time.Duration) *Scanner {
	return &Scanner{prober: prober, maxHosts: maxHosts, delay: delay, periodic: true}
}

func (s *Scanner) SetPeriodicEnabled(enabled bool) {
	s.mu.Lock()
	s.periodic = enabled
	s.mu.Unlock()
}

func (s *Scanner) PeriodicEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.periodic
}

func (s *Scanner) Scanning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func (s *Scanner) SetObserver(observer func(ScanEvent)) {
	s.mu.Lock()
	s.observer = observer
	s.mu.Unlock()
}

// Scan performs one bounded scan. Only one scan may run at a time, preventing
// periodic and user-requested scans from overlapping.
func (s *Scanner) Scan(ctx context.Context, prefix netip.Prefix) (err error) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return ErrScanInProgress
	}
	s.running = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	hosts, err := network.IPv4Hosts(prefix, s.maxHosts)
	if err != nil {
		return err
	}
	started := time.Now().UTC()
	s.notify(ScanEvent{Kind: ScanStarted, Prefix: prefix.Masked(), At: started})
	probed := 0
	defer func() {
		event := ScanEvent{
			Kind: ScanCompleted, Prefix: prefix.Masked(), At: time.Now().UTC(),
			Probed: probed, Duration: time.Since(started), Err: err,
		}
		if err != nil {
			event.Kind = ScanFailed
		}
		s.notify(event)
	}()
	for i, host := range hosts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.prober.Probe(ctx, host); err != nil {
			return err
		}
		probed++
		if s.delay > 0 && i < len(hosts)-1 {
			timer := time.NewTimer(s.delay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return nil
}

func (s *Scanner) notify(event ScanEvent) {
	s.mu.Lock()
	observer := s.observer
	s.mu.Unlock()
	if observer != nil {
		observer(event)
	}
}

// Run scans immediately and then periodically until ctx is cancelled.
func (s *Scanner) Run(ctx context.Context, prefix netip.Prefix, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("scan interval must be positive")
	}
	if err := s.Scan(ctx, prefix); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if !s.PeriodicEnabled() {
				continue
			}
			if err := s.Scan(ctx, prefix); err != nil {
				return err
			}
		}
	}
}
