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

func (m *Manager) Set(mac net.HardwareAddr, policy Policy) error {
	key, err := normalizeDeviceMAC(mac)
	if err != nil {
		return err
	}
	limiter, err := NewLimiter(policy)
	if err != nil {
		return err
	}
	policy = policy.normalized()
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
	return managed.limiter.Wait(ctx, direction, packetBytes)
}

func (m *Manager) Snapshot() []DevicePolicy {
	m.mu.RLock()
	result := make([]DevicePolicy, 0, len(m.policies))
	for mac, managed := range m.policies {
		result = append(result, DevicePolicy{MAC: mac, Policy: managed.policy})
	}
	m.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].MAC < result[j].MAC })
	return result
}
