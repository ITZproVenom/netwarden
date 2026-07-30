package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"

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
}

type BandwidthTarget struct {
	IP     netip.Addr       `json:"ip"`
	MAC    net.HardwareAddr `json:"mac"`
	Policy shaping.Policy   `json:"policy"`
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
	if err := s.controller.SetBandwidthLimit(ctx, resolved.IP, resolved.MAC, policy); err != nil {
		return fmt.Errorf("set bandwidth limit: %w", err)
	}
	s.mu.Lock()
	s.active[resolved.MAC.String()] = BandwidthTarget{IP: resolved.IP, MAC: append(net.HardwareAddr(nil), resolved.MAC...), Policy: policy}
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
		removeErr = s.monitor.StartBandwidthMonitor(ctx, target.IP, target.MAC)
	} else {
		removeErr = s.controller.RemoveBandwidthLimit(ctx, target.IP, target.MAC)
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
		if err := s.monitor.StartBandwidthMonitor(ctx, resolved.IP, resolved.MAC); err != nil {
			return fmt.Errorf("start bandwidth monitor: %w", err)
		}
	}
	s.mu.Lock()
	s.monitored[key] = BandwidthTarget{IP: resolved.IP, MAC: append(net.HardwareAddr(nil), resolved.MAC...)}
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
	if err := s.monitor.StopBandwidthMonitor(ctx, target.IP, target.MAC); err != nil {
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
		result = append(result, target)
	}
	s.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].MAC.String() < result[j].MAC.String() })
	return result
}

func (s *BandwidthService) Traffic(ctx context.Context) ([]shaping.DeviceTrafficStats, error) {
	if !s.MonitoringAvailable() {
		return nil, ErrBandwidthMonitoringUnavailable
	}
	return s.monitor.BandwidthTraffic(ctx)
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

func (s *BandwidthService) resolve(target ControlTarget) (ControlTarget, error) {
	key, err := bandwidthMACKey(target.MAC)
	if err != nil || !target.IP.Is4() {
		return ControlTarget{}, ErrBandwidthTarget
	}
	current, found := s.devices.Get(key)
	if !found || !current.Online || current.Role != device.RolePeer || current.IP != target.IP {
		return ControlTarget{}, ErrBandwidthTarget
	}
	mac, err := net.ParseMAC(current.MAC)
	if err != nil {
		return ControlTarget{}, ErrBandwidthTarget
	}
	return ControlTarget{IP: current.IP, MAC: mac}, nil
}

func bandwidthMACKey(mac net.HardwareAddr) (string, error) {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return "", ErrBandwidthTarget
	}
	return mac.String(), nil
}
