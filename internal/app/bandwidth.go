package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/shaping"
)

var (
	ErrBandwidthUnavailable           = errors.New("bandwidth control is unavailable for the active capture backend")
	ErrBandwidthTarget                = errors.New("bandwidth target is not an eligible online peer")
	ErrBandwidthConflict              = errors.New("device has an active disconnect control")
	ErrBandwidthMonitoringUnavailable = errors.New("bandwidth monitoring is unavailable for the active capture backend")
)

type BandwidthController interface {
	SetBandwidthLimit(context.Context, netip.Addr, net.HardwareAddr, shaping.Policy) error
	RemoveBandwidthLimit(context.Context, netip.Addr, net.HardwareAddr) error
}

type BandwidthMonitorController interface {
	StartBandwidthMonitor(context.Context, netip.Addr, net.HardwareAddr) error
	StopBandwidthMonitor(context.Context, netip.Addr, net.HardwareAddr) error
	BandwidthTraffic(context.Context) ([]shaping.DeviceTrafficStats, error)
	BandwidthForwarderStats(context.Context) (shaping.ForwarderStats, error)
}

type deviceBandwidthController interface {
	SetDeviceBandwidthLimit(context.Context, []netip.Addr, net.HardwareAddr, shaping.Policy) error
	RemoveDeviceBandwidthLimit(context.Context, []netip.Addr, net.HardwareAddr) error
}

type deviceBandwidthMonitorController interface {
	StartDeviceBandwidthMonitor(context.Context, []netip.Addr, net.HardwareAddr) error
	StopDeviceBandwidthMonitor(context.Context, []netip.Addr, net.HardwareAddr) error
}

type BandwidthTarget struct {
	IP        netip.Addr       `json:"ip"`
	Addresses []netip.Addr     `json:"addresses,omitempty"`
	MAC       net.HardwareAddr `json:"mac"`
	Policy    shaping.Policy   `json:"policy"`
}

type bandwidthDeviceSource interface {
	Get(string) (device.Device, bool)
}

// BandwidthService owns the application view of helper policies for one
// runtime generation. Policies are deliberately not persisted across restarts.
type BandwidthService struct {
	controller BandwidthController
	monitor    BandwidthMonitorController
	devices    bandwidthDeviceSource
	blocked    func(net.HardwareAddr) bool

	opMu      sync.Mutex
	mu        sync.RWMutex
	active    map[string]BandwidthTarget
	monitored map[string]BandwidthTarget
}

func NewBandwidthService(controller BandwidthController, devices bandwidthDeviceSource, blocked func(net.HardwareAddr) bool) *BandwidthService {
	monitor, _ := controller.(BandwidthMonitorController)
	return &BandwidthService{controller: controller, monitor: monitor, devices: devices, blocked: blocked,
		active: make(map[string]BandwidthTarget), monitored: make(map[string]BandwidthTarget)}
}

func (s *BandwidthService) Available() bool           { return s != nil && s.controller != nil }
func (s *BandwidthService) MonitoringAvailable() bool { return s != nil && s.monitor != nil }

func (s *BandwidthService) Set(ctx context.Context, target ControlTarget, policy shaping.Policy) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if !s.Available() {
		return ErrBandwidthUnavailable
	}
	resolved, err := s.resolve(target)
	if err != nil {
		return err
	}
	if s.blocked != nil && s.blocked(resolved.MAC) {
		return ErrBandwidthConflict
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("bandwidth policy: %w", err)
	}
	policy = policy.Effective()
	if err := s.setLimit(ctx, resolved, policy); err != nil {
		return fmt.Errorf("set bandwidth limit: %w", err)
	}
	s.mu.Lock()
	resolved.Policy = policy
	s.active[resolved.MAC.String()] = resolved
	s.mu.Unlock()
	return nil
}

// Remove uses the recorded IP so recovery remains possible when a device has
// gone offline or its current registry identity has changed.
func (s *BandwidthService) Remove(ctx context.Context, mac net.HardwareAddr) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.remove(ctx, mac)
}

func (s *BandwidthService) remove(ctx context.Context, mac net.HardwareAddr) error {
	if !s.Available() {
		return ErrBandwidthUnavailable
	}
	key, err := bandwidthMACKey(mac)
	if err != nil {
		return err
	}
	s.mu.RLock()
	target, found := s.active[key]
	s.mu.RUnlock()
	if !found {
		return nil
	}
	s.mu.RLock()
	_, keepMonitoring := s.monitored[key]
	s.mu.RUnlock()
	var removeErr error
	if keepMonitoring {
		removeErr = s.startMonitor(ctx, target)
	} else {
		removeErr = s.removeLimit(ctx, target)
	}
	if removeErr != nil {
		return fmt.Errorf("remove bandwidth limit: %w", removeErr)
	}
	s.mu.Lock()
	delete(s.active, key)
	s.mu.Unlock()
	return nil
}

func (s *BandwidthService) StartMonitoring(ctx context.Context, target ControlTarget) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if !s.MonitoringAvailable() {
		return ErrBandwidthMonitoringUnavailable
	}
	resolved, err := s.resolve(target)
	if err != nil {
		return err
	}
	if s.blocked != nil && s.blocked(resolved.MAC) {
		return ErrBandwidthConflict
	}
	key, _ := bandwidthMACKey(resolved.MAC)
	s.mu.RLock()
	_, limited := s.active[key]
	s.mu.RUnlock()
	if !limited {
		if err := s.startMonitor(ctx, resolved); err != nil {
			return fmt.Errorf("start bandwidth monitor: %w", err)
		}
	}
	s.mu.Lock()
	s.monitored[key] = resolved
	s.mu.Unlock()
	return nil
}

func (s *BandwidthService) StopMonitoring(ctx context.Context, mac net.HardwareAddr) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if !s.MonitoringAvailable() {
		return ErrBandwidthMonitoringUnavailable
	}
	key, err := bandwidthMACKey(mac)
	if err != nil {
		return err
	}
	s.mu.RLock()
	target, found := s.monitored[key]
	_, limited := s.active[key]
	s.mu.RUnlock()
	if !found {
		return nil
	}
	if limited {
		return errors.New("remove the bandwidth limit before stopping monitoring")
	}
	if err := s.stopMonitor(ctx, target); err != nil {
		return fmt.Errorf("stop bandwidth monitor: %w", err)
	}
	s.mu.Lock()
	delete(s.monitored, key)
	s.mu.Unlock()
	return nil
}

func (s *BandwidthService) ClearMonitoring(ctx context.Context) error {
	if !s.MonitoringAvailable() {
		return nil
	}
	var result error
	for _, target := range s.MonitoringSnapshot() {
		if err := s.StopMonitoring(ctx, target.MAC); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (s *BandwidthService) MonitoringSnapshot() []BandwidthTarget {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	result := make([]BandwidthTarget, 0, len(s.monitored))
	for _, target := range s.monitored {
		target.MAC = append(net.HardwareAddr(nil), target.MAC...)
		target.Addresses = append([]netip.Addr(nil), target.Addresses...)
		result = append(result, target)
	}
	s.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].MAC.String() < result[j].MAC.String() })
	return result
}

func (s *BandwidthService) ReconcileDevice(ctx context.Context, current device.Device) error {
	mac, err := net.ParseMAC(current.MAC)
	if err != nil || !current.Online || current.Role != device.RolePeer {
		return nil
	}
	key, _ := bandwidthMACKey(mac)
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.mu.RLock()
	monitored, isMonitored := s.monitored[key]
	limited, isLimited := s.active[key]
	s.mu.RUnlock()
	addresses := eligibleBandwidthAddresses(current)
	if !isMonitored || sameAddresses(monitored.Addresses, addresses) {
		return nil
	}
	if isLimited {
		if err := s.removeLimit(ctx, limited); err != nil {
			return fmt.Errorf("restore old monitored address: %w", err)
		}
		replacement := BandwidthTarget{IP: current.IP, Addresses: addresses, MAC: mac, Policy: limited.Policy}
		if err := s.setLimit(ctx, replacement, limited.Policy); err != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			rollbackErr := s.setLimit(rollbackCtx, limited, limited.Policy)
			cancel()
			return errors.Join(fmt.Errorf("move bandwidth limit to new address: %w", err), rollbackErr)
		}
		limited.IP = current.IP
		limited.Addresses = addresses
		s.mu.Lock()
		s.active[key] = limited
		s.mu.Unlock()
	} else {
		if err := s.stopMonitor(ctx, monitored); err != nil {
			return fmt.Errorf("restore old monitored address: %w", err)
		}
		replacement := BandwidthTarget{IP: current.IP, Addresses: addresses, MAC: mac}
		if err := s.startMonitor(ctx, replacement); err != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			rollbackErr := s.startMonitor(rollbackCtx, monitored)
			cancel()
			return errors.Join(fmt.Errorf("move bandwidth monitor to new address: %w", err), rollbackErr)
		}
	}
	monitored.IP = current.IP
	monitored.Addresses = addresses
	s.mu.Lock()
	s.monitored[key] = monitored
	s.mu.Unlock()
	return nil
}

func (s *BandwidthService) Traffic(ctx context.Context) ([]shaping.DeviceTrafficStats, error) {
	if !s.MonitoringAvailable() {
		return nil, ErrBandwidthMonitoringUnavailable
	}
	return s.monitor.BandwidthTraffic(ctx)
}

func (s *BandwidthService) BandwidthTraffic(ctx context.Context) ([]shaping.DeviceTrafficStats, error) {
	return s.Traffic(ctx)
}

func (s *BandwidthService) ForwarderStats(ctx context.Context) (shaping.ForwarderStats, error) {
	if !s.MonitoringAvailable() {
		return shaping.ForwarderStats{}, ErrBandwidthMonitoringUnavailable
	}
	return s.monitor.BandwidthForwarderStats(ctx)
}

func (s *BandwidthService) Clear(ctx context.Context) error {
	if !s.Available() {
		return nil
	}
	var result error
	for _, target := range s.Snapshot() {
		s.opMu.Lock()
		err := s.remove(ctx, target.MAC)
		s.opMu.Unlock()
		if err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (s *BandwidthService) Snapshot() []BandwidthTarget {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	result := make([]BandwidthTarget, 0, len(s.active))
	for _, target := range s.active {
		target.MAC = append(net.HardwareAddr(nil), target.MAC...)
		target.Addresses = append([]netip.Addr(nil), target.Addresses...)
		result = append(result, target)
	}
	s.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].MAC.String() < result[j].MAC.String() })
	return result
}

func (s *BandwidthService) Contains(mac net.HardwareAddr) bool {
	if s == nil {
		return false
	}
	key, err := bandwidthMACKey(mac)
	if err != nil {
		return false
	}
	s.mu.RLock()
	_, found := s.active[key]
	s.mu.RUnlock()
	return found
}

func (s *BandwidthService) resolve(target ControlTarget) (BandwidthTarget, error) {
	key, err := bandwidthMACKey(target.MAC)
	if err != nil || !target.IP.IsValid() {
		return BandwidthTarget{}, ErrBandwidthTarget
	}
	current, found := s.devices.Get(key)
	if !found || !current.Online || current.Role != device.RolePeer || current.IP != target.IP {
		return BandwidthTarget{}, ErrBandwidthTarget
	}
	mac, err := net.ParseMAC(current.MAC)
	if err != nil {
		return BandwidthTarget{}, ErrBandwidthTarget
	}
	addresses := eligibleBandwidthAddresses(current)
	if len(addresses) == 0 {
		return BandwidthTarget{}, ErrBandwidthTarget
	}
	return BandwidthTarget{IP: current.IP, Addresses: addresses, MAC: mac}, nil
}

func eligibleBandwidthAddresses(current device.Device) []netip.Addr {
	addresses := append([]netip.Addr(nil), current.Addresses...)
	if len(addresses) == 0 && current.IP.IsValid() {
		addresses = []netip.Addr{current.IP}
	}
	result := addresses[:0]
	for _, address := range addresses {
		if address.Is4() || address.Is6() && !address.IsMulticast() && !address.IsUnspecified() {
			result = append(result, address)
		}
	}
	return result
}

func sameAddresses(left, right []netip.Addr) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[netip.Addr]struct{}, len(left))
	for _, a := range left {
		seen[a] = struct{}{}
	}
	for _, a := range right {
		if _, ok := seen[a]; !ok {
			return false
		}
	}
	return true
}

func (s *BandwidthService) setLimit(ctx context.Context, target BandwidthTarget, policy shaping.Policy) error {
	if controller, ok := s.controller.(deviceBandwidthController); ok {
		return controller.SetDeviceBandwidthLimit(ctx, target.Addresses, target.MAC, policy)
	}
	return s.controller.SetBandwidthLimit(ctx, target.IP, target.MAC, policy)
}
func (s *BandwidthService) removeLimit(ctx context.Context, target BandwidthTarget) error {
	if controller, ok := s.controller.(deviceBandwidthController); ok {
		return controller.RemoveDeviceBandwidthLimit(ctx, target.Addresses, target.MAC)
	}
	return s.controller.RemoveBandwidthLimit(ctx, target.IP, target.MAC)
}
func (s *BandwidthService) startMonitor(ctx context.Context, target BandwidthTarget) error {
	if controller, ok := s.monitor.(deviceBandwidthMonitorController); ok {
		return controller.StartDeviceBandwidthMonitor(ctx, target.Addresses, target.MAC)
	}
	return s.monitor.StartBandwidthMonitor(ctx, target.IP, target.MAC)
}
func (s *BandwidthService) stopMonitor(ctx context.Context, target BandwidthTarget) error {
	if controller, ok := s.monitor.(deviceBandwidthMonitorController); ok {
		return controller.StopDeviceBandwidthMonitor(ctx, target.Addresses, target.MAC)
	}
	return s.monitor.StopBandwidthMonitor(ctx, target.IP, target.MAC)
}

func bandwidthMACKey(mac net.HardwareAddr) (string, error) {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return "", ErrBandwidthTarget
	}
	return mac.String(), nil
}
