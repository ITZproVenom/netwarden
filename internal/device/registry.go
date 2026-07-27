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

type Metadata struct {
	Name   string
	Vendor string
}

type ChangeKind uint8

const (
	ChangeDiscovered ChangeKind = iota + 1
	ChangeReturnedOnline
	ChangeAddressChanged
	ChangeIPConflict
)

type Change struct {
	Kind       ChangeKind
	Device     Device
	Related    *Device
	PreviousIP netip.Addr
}

type ObservationResult struct {
	Device  Device
	Changes []Change
}

type record struct {
	Device
}

type Registry struct {
	mu      sync.RWMutex
	devices map[string]*record
	byIP    map[netip.Addr]string
}

func NewRegistry() *Registry {
	return &Registry{devices: make(map[string]*record), byIP: make(map[netip.Addr]string)}
}

// Restore imports durable peer history. Restored peers begin offline until a
// live packet confirms their presence in the current runtime.
func (r *Registry) Restore(devices []Device) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, snapshot := range devices {
		mac, err := net.ParseMAC(snapshot.MAC)
		if err != nil || len(mac) != 6 || !snapshot.IP.Is4() || snapshot.Role != RolePeer {
			continue
		}
		snapshot.MAC = canonicalMAC(mac)
		snapshot.Online = false
		r.devices[snapshot.MAC] = &record{Device: snapshot}
		r.byIP[snapshot.IP] = snapshot.MAC
	}
}

// Observe inserts or refreshes a device and returns its new snapshot. changed
// reports whether observers should refresh their view.
func (r *Registry) Observe(observation Observation) (snapshot Device, changed bool, err error) {
	result, err := r.ObserveDetailed(observation)
	return result.Device, len(result.Changes) > 0, err
}

// ObserveDetailed records an observation and describes every identity or
// lifecycle transition caused by it.
func (r *Registry) ObserveDetailed(observation Observation) (ObservationResult, error) {
	if !observation.IP.IsValid() || !observation.IP.Is4() || len(observation.MAC) != 6 {
		return ObservationResult{}, ErrInvalidObservation
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
		snapshot := Device{
			IP: observation.IP, MAC: mac, Name: observation.IP.String(),
			FirstSeen: seenAt, LastSeen: seenAt, Online: true,
		}
		result := ObservationResult{Device: snapshot}
		if previousMAC, occupied := r.byIP[observation.IP]; occupied && previousMAC != mac {
			if previous, exists := r.devices[previousMAC]; exists {
				previous.Online = false
				related := previous.Device
				result.Changes = append(result.Changes, Change{
					Kind: ChangeIPConflict, Device: snapshot, Related: &related,
				})
			}
		}
		r.devices[mac] = &record{Device: snapshot}
		r.byIP[observation.IP] = mac
		result.Changes = append(result.Changes, Change{Kind: ChangeDiscovered, Device: snapshot})
		return result, nil
	}

	result := ObservationResult{}
	wasOnline := existing.Online
	previousIP := existing.IP
	if previousMAC, occupied := r.byIP[observation.IP]; occupied && previousMAC != mac {
		if previous, exists := r.devices[previousMAC]; exists {
			previous.Online = false
			related := previous.Device
			result.Changes = append(result.Changes, Change{
				Kind: ChangeIPConflict, Device: existing.Device, Related: &related,
			})
		}
	}
	if previousIP != observation.IP {
		if indexedMAC := r.byIP[previousIP]; indexedMAC == mac {
			delete(r.byIP, previousIP)
		}
		if existing.Name == previousIP.String() {
			existing.Name = observation.IP.String()
		}
		existing.IP = observation.IP
	}
	r.byIP[observation.IP] = mac
	if seenAt.After(existing.LastSeen) {
		existing.LastSeen = seenAt
	}
	existing.Online = true
	result.Device = existing.Device
	for i := range result.Changes {
		result.Changes[i].Device = existing.Device
	}
	if previousIP != observation.IP {
		result.Changes = append(result.Changes, Change{
			Kind: ChangeAddressChanged, Device: existing.Device, PreviousIP: previousIP,
		})
	}
	if !wasOnline {
		result.Changes = append(result.Changes, Change{Kind: ChangeReturnedOnline, Device: existing.Device})
	}
	return result, nil
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

// RemoveStale permanently removes offline peer records after retention.
func (r *Registry) RemoveStale(now time.Time, retention time.Duration) []Device {
	if retention <= 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var removed []Device
	for mac, current := range r.devices {
		if current.Role != RolePeer || current.Online || now.Sub(current.LastSeen) < retention {
			continue
		}
		removed = append(removed, current.Device)
		delete(r.devices, mac)
		if r.byIP[current.IP] == mac {
			delete(r.byIP, current.IP)
		}
	}
	return removed
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

// ApplyMetadata enriches an existing record without exposing mutable state.
func (r *Registry) ApplyMetadata(mac string, metadata Metadata) (Device, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.devices[strings.ToLower(mac)]
	if !ok {
		return Device{}, false
	}
	changed := false
	if metadata.Name != "" && current.Name != metadata.Name {
		current.Name = metadata.Name
		changed = true
	}
	if metadata.Vendor != "" && current.Vendor != metadata.Vendor {
		current.Vendor = metadata.Vendor
		changed = true
	}
	return current.Device, changed
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

func (r *Registry) Get(mac string) (Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	current, ok := r.devices[strings.ToLower(mac)]
	if !ok {
		return Device{}, false
	}
	return current.Device, true
}

func canonicalMAC(mac net.HardwareAddr) string {
	return strings.ToLower(mac.String())
}
