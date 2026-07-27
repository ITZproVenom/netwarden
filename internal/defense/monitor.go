// Package defense contains passive network-integrity monitoring. It does not
// transmit packets or modify host networking state.
package defense

import (
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amdzy/NetWarden/internal/packet"
)

type EventKind uint8

const (
	GatewayIdentityConflict EventKind = iota + 1
	GatewayIdentityRestored
)

type BaselineSource uint8

const (
	BaselineLearned BaselineSource = iota + 1
	BaselinePinned
)

type Conflict struct {
	GatewayIP  netip.Addr
	ClaimedMAC string
	FirstSeen  time.Time
	LastSeen   time.Time
	Count      uint64
	Active     bool
}

type Event struct {
	Kind        EventKind
	ObservedAt  time.Time
	GatewayIP   netip.Addr
	ExpectedMAC string
	ClaimedMAC  string
	Operation   uint16
	Baseline    BaselineSource
	Count       uint64
	FirstSeen   time.Time
}

type Monitor struct {
	gatewayIP  netip.Addr
	gatewayMAC string
	cooldown   time.Duration
	events     chan Event
	baseline   BaselineSource

	mu      sync.Mutex
	history map[string]Conflict
	dropped atomic.Uint64
}

func NewMonitor(gatewayIP netip.Addr, gatewayMAC net.HardwareAddr, cooldown time.Duration) *Monitor {
	return newMonitor(gatewayIP, gatewayMAC, cooldown, BaselineLearned)
}

func NewPinnedMonitor(gatewayIP netip.Addr, gatewayMAC net.HardwareAddr, cooldown time.Duration) *Monitor {
	return newMonitor(gatewayIP, gatewayMAC, cooldown, BaselinePinned)
}

func newMonitor(gatewayIP netip.Addr, gatewayMAC net.HardwareAddr, cooldown time.Duration, baseline BaselineSource) *Monitor {
	if cooldown <= 0 {
		cooldown = 5 * time.Second
	}
	return &Monitor{
		gatewayIP:  gatewayIP,
		gatewayMAC: strings.ToLower(gatewayMAC.String()),
		cooldown:   cooldown,
		events:     make(chan Event, 32),
		baseline:   baseline,
		history:    make(map[string]Conflict),
	}
}

func (m *Monitor) Events() <-chan Event  { return m.events }
func (m *Monitor) DroppedEvents() uint64 { return m.dropped.Load() }

func (m *Monitor) History() []Conflict {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]Conflict, 0, len(m.history))
	for _, conflict := range m.history {
		result = append(result, conflict)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].FirstSeen.Before(result[j].FirstSeen) })
	return result
}

func (m *Monitor) RestoreHistory(conflicts []Conflict) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, conflict := range conflicts {
		if conflict.ClaimedMAC != "" && conflict.GatewayIP == m.gatewayIP {
			m.history[strings.ToLower(conflict.ClaimedMAC)] = conflict
		}
	}
}

func (m *Monitor) ObserveGatewayClaim(mac net.HardwareAddr, observedAt time.Time) {
	m.observeClaim(strings.ToLower(mac.String()), 0, observedAt)
}

func (m *Monitor) Observe(message packet.ARP, observedAt time.Time) {
	if message.SenderIP != m.gatewayIP {
		return
	}
	claimed := strings.ToLower(message.SenderMAC.String())
	m.observeClaim(claimed, message.Operation, observedAt)
}

func (m *Monitor) observeClaim(claimed string, operation uint16, observedAt time.Time) {
	if claimed == "" {
		return
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	observedAt = observedAt.UTC()

	m.mu.Lock()
	if claimed == m.gatewayMAC {
		restored := false
		for key, conflict := range m.history {
			if conflict.Active {
				conflict.Active = false
				m.history[key] = conflict
				restored = true
			}
		}
		m.mu.Unlock()
		if restored {
			m.emit(Event{Kind: GatewayIdentityRestored, ObservedAt: observedAt, GatewayIP: m.gatewayIP,
				ExpectedMAC: m.gatewayMAC, ClaimedMAC: claimed, Operation: operation, Baseline: m.baseline})
		}
		return
	}
	conflict, exists := m.history[claimed]
	emit := !exists || observedAt.Sub(conflict.LastSeen) >= m.cooldown
	if !exists {
		conflict = Conflict{GatewayIP: m.gatewayIP, ClaimedMAC: claimed, FirstSeen: observedAt}
	}
	conflict.LastSeen = observedAt
	conflict.Count++
	conflict.Active = true
	m.history[claimed] = conflict
	m.mu.Unlock()
	if !emit {
		return
	}

	m.emit(Event{
		Kind: GatewayIdentityConflict, ObservedAt: observedAt.UTC(),
		GatewayIP: m.gatewayIP, ExpectedMAC: m.gatewayMAC,
		ClaimedMAC: claimed, Operation: operation, Baseline: m.baseline,
		Count: conflict.Count, FirstSeen: conflict.FirstSeen,
	})
}

func (m *Monitor) emit(event Event) {
	select {
	case m.events <- event:
	default:
		m.dropped.Add(1)
	}
}
