// Package defense contains passive network-integrity monitoring. It does not
// transmit packets or modify host networking state.
package defense

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/packet"
)

type EventKind uint8

const (
	GatewayIdentityConflict EventKind = iota + 1
)

type Event struct {
	Kind        EventKind
	ObservedAt  time.Time
	GatewayIP   netip.Addr
	ExpectedMAC string
	ClaimedMAC  string
	Operation   uint16
}

type Monitor struct {
	gatewayIP  netip.Addr
	gatewayMAC string
	cooldown   time.Duration
	events     chan Event

	mu       sync.Mutex
	lastSeen map[string]time.Time
}

func NewMonitor(gatewayIP netip.Addr, gatewayMAC net.HardwareAddr, cooldown time.Duration) *Monitor {
	if cooldown <= 0 {
		cooldown = 5 * time.Second
	}
	return &Monitor{
		gatewayIP:  gatewayIP,
		gatewayMAC: strings.ToLower(gatewayMAC.String()),
		cooldown:   cooldown,
		events:     make(chan Event, 32),
		lastSeen:   make(map[string]time.Time),
	}
}

func (m *Monitor) Events() <-chan Event { return m.events }

func (m *Monitor) Observe(message packet.ARP, observedAt time.Time) {
	if message.SenderIP != m.gatewayIP {
		return
	}
	claimed := strings.ToLower(message.SenderMAC.String())
	if claimed == "" || claimed == m.gatewayMAC {
		return
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}

	m.mu.Lock()
	previous, duplicate := m.lastSeen[claimed]
	if duplicate && observedAt.Sub(previous) < m.cooldown {
		m.mu.Unlock()
		return
	}
	m.lastSeen[claimed] = observedAt
	m.mu.Unlock()

	event := Event{
		Kind: GatewayIdentityConflict, ObservedAt: observedAt.UTC(),
		GatewayIP: m.gatewayIP, ExpectedMAC: m.gatewayMAC,
		ClaimedMAC: claimed, Operation: message.Operation,
	}
	select {
	case m.events <- event:
	default:
	}
}
