package shaping

import (
	"context"
	"net"
	"sort"
	"sync"
)

type DevicePolicy struct {
	MAC    string `json:"mac"`
	Policy Policy `json:"policy"`
}

type managedPolicy struct {
	policy  Policy
	limiter *Limiter
}

// Manager owns live shaping policies. Replacing a policy is atomic for new
// packets; packets already waiting finish against the policy they reserved.
type Manager struct {
	mu       sync.RWMutex
	policies map[string]*managedPolicy
}

func NewManager() *Manager { return &Manager{policies: make(map[string]*managedPolicy)} }

// Track installs an unrestricted forwarding identity. It is intentionally
// separate from Policy validation: monitoring is a forwarding concern, while
// a zero-rate Policy would ambiguously mean both "invalid" and "unlimited".
func (m *Manager) Track(mac net.HardwareAddr) error {
	key, err := normalizeDeviceMAC(mac)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if _, exists := m.policies[key]; !exists {
		m.policies[key] = &managedPolicy{}
	}
	m.mu.Unlock()
	return nil
}

// SetUnrestricted transitions an existing limited identity to monitored-only
// forwarding, or creates it when absent.
func (m *Manager) SetUnrestricted(mac net.HardwareAddr) error {
	key, err := normalizeDeviceMAC(mac)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.policies[key] = &managedPolicy{}
	m.mu.Unlock()
	return nil
}

func (m *Manager) Untrack(mac net.HardwareAddr) error {
	key, err := normalizeDeviceMAC(mac)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if managed := m.policies[key]; managed != nil && managed.limiter == nil {
		delete(m.policies, key)
	}
	m.mu.Unlock()
	return nil
}

func (m *Manager) Limited(mac net.HardwareAddr) bool {
	key, err := normalizeDeviceMAC(mac)
	if err != nil {
		return false
	}
	m.mu.RLock()
	managed := m.policies[key]
	m.mu.RUnlock()
	return managed != nil && managed.limiter != nil
}

func (m *Manager) Set(mac net.HardwareAddr, policy Policy) error {
	key, err := normalizeDeviceMAC(mac)
	if err != nil {
		return err
	}
	limiter, err := NewLimiter(policy)
	if err != nil {
		return err
	}
	policy = policy.Effective()
	m.mu.Lock()
	m.policies[key] = &managedPolicy{policy: policy, limiter: limiter}
	m.mu.Unlock()
	return nil
}

func (m *Manager) Remove(mac net.HardwareAddr) error {
	key, err := normalizeDeviceMAC(mac)
	if err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.policies, key)
	m.mu.Unlock()
	return nil
}

func (m *Manager) Has(mac net.HardwareAddr) bool {
	key, err := normalizeDeviceMAC(mac)
	if err != nil {
		return false
	}
	m.mu.RLock()
	_, found := m.policies[key]
	m.mu.RUnlock()
	return found
}

func (m *Manager) Wait(ctx context.Context, mac net.HardwareAddr, direction Direction, packetBytes int) error {
	key, err := normalizeDeviceMAC(mac)
	if err != nil {
		return err
	}
	if err := validateDirection(direction); err != nil {
		return err
	}
	m.mu.RLock()
	managed := m.policies[key]
	m.mu.RUnlock()
	if managed == nil {
		return ctx.Err()
	}
	if managed.limiter == nil {
		return nil
	}
	return managed.limiter.Wait(ctx, direction, packetBytes)
}

func (m *Manager) Snapshot() []DevicePolicy {
	m.mu.RLock()
	result := make([]DevicePolicy, 0, len(m.policies))
	for mac, managed := range m.policies {
		if managed.limiter == nil {
			continue
		}
		result = append(result, DevicePolicy{MAC: mac, Policy: managed.policy})
	}
	m.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].MAC < result[j].MAC })
	return result
}
