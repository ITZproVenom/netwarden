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

// Type is the best-effort category inferred from a device's role and metadata.
// Its empty zero value lets older history files load and is presented as Unknown.
type Type string

const (
	TypeUnknown     Type = "Unknown"
	TypeComputer    Type = "Computer"
	TypePhone       Type = "Phone"
	TypeTablet      Type = "Tablet"
	TypeNetwork     Type = "Network device"
	TypePrinter     Type = "Printer"
	TypeTV          Type = "TV / streaming"
	TypeGameConsole Type = "Game console"
	TypeSpeaker     Type = "Smart speaker"
	TypeCamera      Type = "Camera"
	TypeSmartHome   Type = "Smart home"
)

type Observation struct {
	IP     netip.Addr
	MAC    net.HardwareAddr
	SeenAt time.Time
}

// Device is an immutable snapshot returned to callers.
type Device struct {
	IP netip.Addr
	// Addresses contains every currently known unicast address for the device.
	// IP remains the preferred address for compatibility with callers that can
	// operate on only one address; an IPv4 address is preferred when available.
	Addresses []netip.Addr
	MAC       string
	Name      string
	Vendor    string
	Type      Type
	Role      Role
	FirstSeen time.Time
	LastSeen  time.Time
	Online    bool
}

type Metadata struct {
	Name   string
	Vendor string
	Type   Type
}

type ChangeKind uint8

const (
	ChangeDiscovered ChangeKind = iota + 1
	ChangeReturnedOnline
	ChangeAddressChanged
	ChangeAddressAdded
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
	addressSeen map[netip.Addr]time.Time
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
		if err != nil || len(mac) != 6 || !validDeviceAddress(snapshot.IP) || snapshot.Role != RolePeer {
			continue
		}
		snapshot.Addresses = normalizeAddresses(snapshot.IP, snapshot.Addresses)
		snapshot.MAC = canonicalMAC(mac)
		snapshot.Online = false
		seen := make(map[netip.Addr]time.Time, len(snapshot.Addresses))
		for _, address := range snapshot.Addresses {
			r.byIP[address] = snapshot.MAC
			seen[address] = snapshot.LastSeen
		}
		r.devices[snapshot.MAC] = &record{Device: snapshot, addressSeen: seen}
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
	if !validDeviceAddress(observation.IP) || len(observation.MAC) != 6 {
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
			IP: observation.IP, Addresses: []netip.Addr{observation.IP}, MAC: mac, Name: observation.IP.String(),
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
		r.devices[mac] = &record{Device: snapshot, addressSeen: map[netip.Addr]time.Time{observation.IP: seenAt}}
		r.byIP[observation.IP] = mac
		result.Changes = append(result.Changes, Change{Kind: ChangeDiscovered, Device: snapshot})
		return cloneObservationResult(result), nil
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
	addressAdded := !containsAddress(existing.Addresses, observation.IP)
	if addressAdded {
		// IPv4 leases are treated as replacements. IPv6 devices legitimately use
		// several addresses at once (link-local, stable, and privacy addresses).
		if observation.IP.Is4() {
			for _, address := range existing.Addresses {
				if address.Is4() && r.byIP[address] == mac {
					delete(r.byIP, address)
				}
				if address.Is4() {
					delete(existing.addressSeen, address)
				}
			}
			existing.Addresses = removeFamily(existing.Addresses, true)
		}
		existing.Addresses = append(existing.Addresses, observation.IP)
		existing.IP = preferredAddress(existing.Addresses)
		if existing.Name == previousIP.String() && existing.IP != previousIP {
			existing.Name = existing.IP.String()
		}
	}
	r.byIP[observation.IP] = mac
	if existing.addressSeen == nil {
		existing.addressSeen = make(map[netip.Addr]time.Time)
	}
	existing.addressSeen[observation.IP] = seenAt
	if seenAt.After(existing.LastSeen) {
		existing.LastSeen = seenAt
	}
	existing.Online = true
	result.Device = existing.Device
	for i := range result.Changes {
		result.Changes[i].Device = existing.Device
	}
	if existing.IP != previousIP {
		result.Changes = append(result.Changes, Change{
			Kind: ChangeAddressChanged, Device: existing.Device, PreviousIP: previousIP,
		})
	} else if addressAdded {
		result.Changes = append(result.Changes, Change{Kind: ChangeAddressAdded, Device: existing.Device})
	}
	if !wasOnline {
		result.Changes = append(result.Changes, Change{Kind: ChangeReturnedOnline, Device: existing.Device})
	}
	return cloneObservationResult(result), nil
}

// ExpireIPv6Addresses removes stale secondary IPv6 addresses while retaining
// at least one usable identity for each device. This bounds privacy-address
// growth independently from whole-device retention.
func (r *Registry) ExpireIPv6Addresses(now time.Time, retention time.Duration) []Device {
	if retention <= 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var changed []Device
	for mac, current := range r.devices {
		if len(current.Addresses) <= 1 {
			continue
		}
		previousIP := current.IP
		kept := make([]netip.Addr, 0, len(current.Addresses))
		removed := false
		for _, address := range current.Addresses {
			seenAt := current.addressSeen[address]
			stale := address.Is6() && address != current.IP && !seenAt.IsZero() && now.Sub(seenAt) >= retention
			if stale {
				delete(current.addressSeen, address)
				if r.byIP[address] == mac {
					delete(r.byIP, address)
				}
				removed = true
				continue
			}
			kept = append(kept, address)
		}
		if !removed || len(kept) == 0 {
			continue
		}
		current.Addresses = kept
		current.IP = preferredAddress(kept)
		if current.Name == previousIP.String() && current.IP != previousIP {
			current.Name = current.IP.String()
		}
		changed = append(changed, cloneDevice(current.Device))
	}
	return changed
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
			changed = append(changed, cloneDevice(current.Device))
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
		removed = append(removed, cloneDevice(current.Device))
		delete(r.devices, mac)
		for _, address := range current.Addresses {
			if r.byIP[address] == mac {
				delete(r.byIP, address)
			}
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
	if role == RoleGateway {
		current.Type = TypeNetwork
	} else if role == RoleLocal {
		current.Type = TypeComputer
	}
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
	if metadata.Type != "" && current.Role == RolePeer && current.Type != metadata.Type {
		current.Type = metadata.Type
		changed = true
	}
	return cloneDevice(current.Device), changed
}

func (r *Registry) Snapshot() []Device {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Device, 0, len(r.devices))
	for _, current := range r.devices {
		result = append(result, cloneDevice(current.Device))
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
	return cloneDevice(current.Device), true
}

func validDeviceAddress(address netip.Addr) bool {
	return address.IsValid() && !address.IsUnspecified() && !address.IsMulticast()
}

func normalizeAddresses(primary netip.Addr, addresses []netip.Addr) []netip.Addr {
	result := make([]netip.Addr, 0, len(addresses)+1)
	if validDeviceAddress(primary) {
		result = append(result, primary)
	}
	for _, address := range addresses {
		if validDeviceAddress(address) && !containsAddress(result, address) {
			result = append(result, address)
		}
	}
	return result
}

func containsAddress(addresses []netip.Addr, candidate netip.Addr) bool {
	for _, address := range addresses {
		if address == candidate {
			return true
		}
	}
	return false
}

func removeFamily(addresses []netip.Addr, ipv4 bool) []netip.Addr {
	result := addresses[:0]
	for _, address := range addresses {
		if address.Is4() != ipv4 {
			result = append(result, address)
		}
	}
	return result
}

func preferredAddress(addresses []netip.Addr) netip.Addr {
	for _, address := range addresses {
		if address.Is4() {
			return address
		}
	}
	if len(addresses) > 0 {
		return addresses[0]
	}
	return netip.Addr{}
}

func cloneDevice(value Device) Device {
	value.Addresses = append([]netip.Addr(nil), value.Addresses...)
	return value
}

func cloneObservationResult(result ObservationResult) ObservationResult {
	result.Device = cloneDevice(result.Device)
	for index := range result.Changes {
		result.Changes[index].Device = cloneDevice(result.Changes[index].Device)
		if result.Changes[index].Related != nil {
			related := cloneDevice(*result.Changes[index].Related)
			result.Changes[index].Related = &related
		}
	}
	return result
}

func canonicalMAC(mac net.HardwareAddr) string {
	return strings.ToLower(mac.String())
}
