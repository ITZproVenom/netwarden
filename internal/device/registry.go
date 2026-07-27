// Package device owns the in-memory view of devices observed on the network.
package device

import (
	"errors"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

var ErrInvalidObservation = errors.New("invalid device observation")

type Role uint8

const (
	RolePeer Role = iota
	RoleLocal
	RoleGateway
)

type Observation struct {
	IP     netip.Addr
	MAC    net.HardwareAddr
	SeenAt time.Time
}

// Device is an immutable snapshot returned to callers.
type Device struct {
	IP        netip.Addr
	MAC       string
	Name      string
	Vendor    string
	Role      Role
	FirstSeen time.Time
	LastSeen  time.Time
	Online    bool
}

type record struct {
	Device
}

type Registry struct {
	mu      sync.RWMutex
	devices map[string]*record
}

func NewRegistry() *Registry {
	return &Registry{devices: make(map[string]*record)}
}

// Observe inserts or refreshes a device and returns its new snapshot. changed
// reports whether observers should refresh their view.
func (r *Registry) Observe(observation Observation) (snapshot Device, changed bool, err error) {
	if !observation.IP.IsValid() || !observation.IP.Is4() || len(observation.MAC) != 6 {
		return Device{}, false, ErrInvalidObservation
	}
	seenAt := observation.SeenAt
	if seenAt.IsZero() {
		seenAt = time.Now().UTC()
	}
	mac := canonicalMAC(observation.MAC)

	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.devices[mac]
	if !ok {
		snapshot = Device{
			IP: observation.IP, MAC: mac, Name: observation.IP.String(),
			FirstSeen: seenAt, LastSeen: seenAt, Online: true,
		}
		r.devices[mac] = &record{Device: snapshot}
		return snapshot, true, nil
	}

	changed = !existing.Online || existing.IP != observation.IP
	existing.IP = observation.IP
	if seenAt.After(existing.LastSeen) {
		existing.LastSeen = seenAt
	}
	existing.Online = true
	return existing.Device, changed, nil
}

// MarkOffline marks peers not seen for at least timeout as offline. It returns
// only devices whose state changed during this call.
func (r *Registry) MarkOffline(now time.Time, timeout time.Duration) []Device {
	if timeout <= 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var changed []Device
	for _, current := range r.devices {
		if current.Role == RolePeer && current.Online && now.Sub(current.LastSeen) >= timeout {
			current.Online = false
			changed = append(changed, current.Device)
		}
	}
	return changed
}

func (r *Registry) SetRole(mac net.HardwareAddr, role Role) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.devices[canonicalMAC(mac)]
	if !ok || current.Role == role {
		return false
	}
	current.Role = role
	return true
}

func (r *Registry) Snapshot() []Device {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Device, 0, len(r.devices))
	for _, current := range r.devices {
		result = append(result, current.Device)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].IP == result[j].IP {
			return result[i].MAC < result[j].MAC
		}
		return result[i].IP.Less(result[j].IP)
	})
	return result
}

func canonicalMAC(mac net.HardwareAddr) string {
	return strings.ToLower(mac.String())
}
