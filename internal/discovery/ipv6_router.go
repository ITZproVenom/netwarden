package discovery

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amdzy/NetWarden/internal/packet"
)

type IPv6RouterEventKind uint8

const (
	IPv6RouterDiscovered IPv6RouterEventKind = iota + 1
	IPv6RouterUpdated
	IPv6RouterWithdrawn
	IPv6RouterIdentityConflict
	IPv6RouterIdentityRestored
)

type IPv6Router struct {
	IP         netip.Addr
	MAC        string
	ExpiresAt  time.Time
	Preference int8
	Prefixes   []IPv6Prefix
}

type IPv6Prefix struct {
	Prefix         netip.Prefix
	OnLink         bool
	Autonomous     bool
	ValidUntil     time.Time
	PreferredUntil time.Time
}

type IPv6Context struct {
	LocalAddresses []netip.Addr
	DefaultRouter  *IPv6Router
	Routers        []IPv6Router
	ConflictCount  int
}

type IPv6RouterEvent struct {
	Kind        IPv6RouterEventKind
	ObservedAt  time.Time
	RouterIP    netip.Addr
	ExpectedMAC string
	ClaimedMAC  string
}

// IPv6RouterTracker learns default routers from validated Router
// Advertisements. It owns selection, lifetime expiry, and identity baselines;
// packet parsing and application presentation remain separate concerns.
type IPv6RouterTracker struct {
	local  []netip.Addr
	events chan IPv6RouterEvent

	mu        sync.Mutex
	routers   map[netip.Addr]IPv6Router
	baselines map[netip.Addr]string
	conflicts map[string]time.Time
	dropped   atomic.Uint64
}

func NewIPv6RouterTracker(local []netip.Addr) *IPv6RouterTracker {
	addresses := make([]netip.Addr, 0, len(local))
	for _, address := range local {
		if address.Is6() && !address.IsMulticast() && !address.IsUnspecified() {
			addresses = append(addresses, address)
		}
	}
	return &IPv6RouterTracker{
		local: addresses, events: make(chan IPv6RouterEvent, 32),
		routers: make(map[netip.Addr]IPv6Router), baselines: make(map[netip.Addr]string),
		conflicts: make(map[string]time.Time),
	}
}

func (t *IPv6RouterTracker) Events() <-chan IPv6RouterEvent { return t.events }
func (t *IPv6RouterTracker) DroppedEvents() uint64          { return t.dropped.Load() }

func (t *IPv6RouterTracker) Observe(message packet.NDP, observedAt time.Time) {
	if message.Type != packet.ICMPv6RouterAdvertisement || !message.SourceIP.Is6() || !message.SourceIP.IsLinkLocalUnicast() {
		return
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	observedAt = observedAt.UTC()
	claimedMAC := strings.ToLower(message.SourceMAC.String())
	if claimedMAC == "" {
		return
	}

	t.mu.Lock()
	expectedMAC, known := t.baselines[message.SourceIP]
	if !known {
		expectedMAC = claimedMAC
		t.baselines[message.SourceIP] = claimedMAC
	}
	conflictKey := message.SourceIP.String() + "|" + claimedMAC
	if claimedMAC != expectedMAC {
		previous, existed := t.conflicts[conflictKey]
		t.conflicts[conflictKey] = observedAt
		t.mu.Unlock()
		if !existed || observedAt.Sub(previous) >= 5*time.Second {
			t.emit(IPv6RouterEvent{Kind: IPv6RouterIdentityConflict, ObservedAt: observedAt,
				RouterIP: message.SourceIP, ExpectedMAC: expectedMAC, ClaimedMAC: claimedMAC})
		}
		return
	}
	restored := false
	for key := range t.conflicts {
		if strings.HasPrefix(key, message.SourceIP.String()+"|") {
			delete(t.conflicts, key)
			restored = true
		}
	}
	_, existed := t.routers[message.SourceIP]
	if message.RouterLifetime == 0 {
		delete(t.routers, message.SourceIP)
		t.mu.Unlock()
		if existed {
			t.emit(IPv6RouterEvent{Kind: IPv6RouterWithdrawn, ObservedAt: observedAt, RouterIP: message.SourceIP,
				ExpectedMAC: expectedMAC, ClaimedMAC: claimedMAC})
		}
		return
	}
	router := IPv6Router{IP: message.SourceIP, MAC: claimedMAC, ExpiresAt: addLifetime(observedAt, message.RouterLifetime), Preference: message.RouterPreference}
	for _, advertised := range message.Prefixes {
		router.Prefixes = append(router.Prefixes, IPv6Prefix{
			Prefix: advertised.Prefix, OnLink: advertised.OnLink, Autonomous: advertised.Autonomous,
			ValidUntil:     addLifetime(observedAt, advertised.ValidLifetime),
			PreferredUntil: addLifetime(observedAt, advertised.PreferredLifetime),
		})
	}
	t.routers[message.SourceIP] = router
	t.mu.Unlock()
	if restored {
		t.emit(IPv6RouterEvent{Kind: IPv6RouterIdentityRestored, ObservedAt: observedAt,
			RouterIP: message.SourceIP, ExpectedMAC: expectedMAC, ClaimedMAC: claimedMAC})
	}
	kind := IPv6RouterDiscovered
	if existed {
		kind = IPv6RouterUpdated
	}
	t.emit(IPv6RouterEvent{Kind: kind, ObservedAt: observedAt, RouterIP: message.SourceIP,
		ExpectedMAC: expectedMAC, ClaimedMAC: claimedMAC})
}

func (t *IPv6RouterTracker) Snapshot(now time.Time) IPv6Context {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	context := IPv6Context{LocalAddresses: append([]netip.Addr(nil), t.local...), ConflictCount: len(t.conflicts)}
	for ip, router := range t.routers {
		if !router.ExpiresAt.After(now) {
			delete(t.routers, ip)
			continue
		}
		context.Routers = append(context.Routers, cloneIPv6Router(router))
	}
	sort.Slice(context.Routers, func(i, j int) bool {
		if context.Routers[i].Preference != context.Routers[j].Preference {
			return context.Routers[i].Preference > context.Routers[j].Preference
		}
		if context.Routers[i].ExpiresAt.Equal(context.Routers[j].ExpiresAt) {
			return context.Routers[i].IP.Less(context.Routers[j].IP)
		}
		return context.Routers[i].ExpiresAt.After(context.Routers[j].ExpiresAt)
	})
	if len(context.Routers) > 0 {
		selected := cloneIPv6Router(context.Routers[0])
		context.DefaultRouter = &selected
	}
	return context
}

func (t *IPv6RouterTracker) emit(event IPv6RouterEvent) {
	select {
	case t.events <- event:
	default:
		t.dropped.Add(1)
	}
}

func addLifetime(at time.Time, lifetime time.Duration) time.Time {
	if lifetime == time.Duration(1<<63-1) {
		return time.Unix(1<<62, 0).UTC()
	}
	return at.Add(lifetime)
}

func cloneIPv6Router(router IPv6Router) IPv6Router {
	router.Prefixes = append([]IPv6Prefix(nil), router.Prefixes...)
	return router
}
