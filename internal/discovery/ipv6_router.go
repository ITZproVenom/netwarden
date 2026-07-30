package discovery

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
	Conflicts      []IPv6RouterConflict
	Baselines      []IPv6RouterIdentity
}

type IPv6RouterIdentity struct {
	RouterIP netip.Addr `json:"router_ip"`
	MAC      string     `json:"mac"`
}

type IPv6RouterConflict struct {
	RouterIP    netip.Addr `json:"router_ip"`
	ExpectedMAC string     `json:"expected_mac"`
	ClaimedMAC  string     `json:"claimed_mac"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	Count       uint64     `json:"count"`
	Active      bool       `json:"active"`
}

type IPv6RouterState struct {
	Baselines []IPv6RouterIdentity `json:"baselines,omitempty"`
	Conflicts []IPv6RouterConflict `json:"conflicts,omitempty"`
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
	conflicts map[string]IPv6RouterConflict
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
		conflicts: make(map[string]IPv6RouterConflict),
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
		conflict, existed := t.conflicts[conflictKey]
		emit := !existed || observedAt.Sub(conflict.LastSeen) >= 5*time.Second
		if !existed {
			conflict = IPv6RouterConflict{RouterIP: message.SourceIP, ExpectedMAC: expectedMAC,
				ClaimedMAC: claimedMAC, FirstSeen: observedAt}
		}
		conflict.LastSeen, conflict.Active = observedAt, true
		conflict.Count++
		t.conflicts[conflictKey] = conflict
		t.mu.Unlock()
		if emit {
			t.emit(IPv6RouterEvent{Kind: IPv6RouterIdentityConflict, ObservedAt: observedAt,
				RouterIP: message.SourceIP, ExpectedMAC: expectedMAC, ClaimedMAC: claimedMAC})
		}
		return
	}
	restored := false
	for key, conflict := range t.conflicts {
		if strings.HasPrefix(key, message.SourceIP.String()+"|") && conflict.Active {
			conflict.Active = false
			t.conflicts[key] = conflict
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
	context := IPv6Context{LocalAddresses: append([]netip.Addr(nil), t.local...)}
	for ip, mac := range t.baselines {
		context.Baselines = append(context.Baselines, IPv6RouterIdentity{RouterIP: ip, MAC: mac})
	}
	sort.Slice(context.Baselines, func(i, j int) bool { return context.Baselines[i].RouterIP.Less(context.Baselines[j].RouterIP) })
	for _, conflict := range t.conflicts {
		context.Conflicts = append(context.Conflicts, conflict)
		if conflict.Active {
			context.ConflictCount++
		}
	}
	sort.Slice(context.Conflicts, func(i, j int) bool { return context.Conflicts[i].FirstSeen.Before(context.Conflicts[j].FirstSeen) })
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

func (t *IPv6RouterTracker) State() IPv6RouterState {
	t.mu.Lock()
	defer t.mu.Unlock()
	state := IPv6RouterState{}
	for ip, mac := range t.baselines {
		state.Baselines = append(state.Baselines, IPv6RouterIdentity{RouterIP: ip, MAC: mac})
	}
	for _, conflict := range t.conflicts {
		state.Conflicts = append(state.Conflicts, conflict)
	}
	sort.Slice(state.Baselines, func(i, j int) bool { return state.Baselines[i].RouterIP.Less(state.Baselines[j].RouterIP) })
	sort.Slice(state.Conflicts, func(i, j int) bool { return state.Conflicts[i].FirstSeen.Before(state.Conflicts[j].FirstSeen) })
	return state
}

func (t *IPv6RouterTracker) RestoreState(state IPv6RouterState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, identity := range state.Baselines {
		if identity.RouterIP.Is6() && identity.RouterIP.IsLinkLocalUnicast() && validMACText(identity.MAC) {
			mac, _ := net.ParseMAC(identity.MAC)
			t.baselines[identity.RouterIP] = strings.ToLower(mac.String())
		}
	}
	for _, conflict := range state.Conflicts {
		if !conflict.RouterIP.Is6() || !conflict.RouterIP.IsLinkLocalUnicast() ||
			!validMACText(conflict.ExpectedMAC) || !validMACText(conflict.ClaimedMAC) {
			continue
		}
		expected, _ := net.ParseMAC(conflict.ExpectedMAC)
		claimed, _ := net.ParseMAC(conflict.ClaimedMAC)
		conflict.ExpectedMAC, conflict.ClaimedMAC = strings.ToLower(expected.String()), strings.ToLower(claimed.String())
		key := conflict.RouterIP.String() + "|" + conflict.ClaimedMAC
		t.conflicts[key] = conflict
	}
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

func validMACText(value string) bool {
	mac, err := net.ParseMAC(value)
	return err == nil && len(mac) == 6 && mac[0]&1 == 0 && value != "00:00:00:00:00:00"
}
