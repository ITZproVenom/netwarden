package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/shaping"
	trafficmetrics "github.com/amdzy/NetWarden/internal/traffic"
)

type recordingBandwidthController struct {
	mu            sync.Mutex
	set           []BandwidthTarget
	removed       []BandwidthTarget
	setErr        error
	remErr        error
	monitored     []BandwidthTarget
	stopped       []BandwidthTarget
	monitorErr    error
	failMonitorIP netip.Addr
}

type recordingDeviceBandwidthController struct {
	recordingBandwidthController
	setAddresses, removedAddresses, monitoredAddresses, stoppedAddresses [][]netip.Addr
}

func (c *recordingDeviceBandwidthController) SetDeviceBandwidthLimit(_ context.Context, addresses []netip.Addr, _ net.HardwareAddr, _ shaping.Policy) error {
	c.setAddresses = append(c.setAddresses, append([]netip.Addr(nil), addresses...))
	return nil
}
func (c *recordingDeviceBandwidthController) RemoveDeviceBandwidthLimit(_ context.Context, addresses []netip.Addr, _ net.HardwareAddr) error {
	c.removedAddresses = append(c.removedAddresses, append([]netip.Addr(nil), addresses...))
	return nil
}
func (c *recordingDeviceBandwidthController) StartDeviceBandwidthMonitor(_ context.Context, addresses []netip.Addr, _ net.HardwareAddr) error {
	c.monitoredAddresses = append(c.monitoredAddresses, append([]netip.Addr(nil), addresses...))
	return nil
}
func (c *recordingDeviceBandwidthController) StopDeviceBandwidthMonitor(_ context.Context, addresses []netip.Addr, _ net.HardwareAddr) error {
	c.stoppedAddresses = append(c.stoppedAddresses, append([]netip.Addr(nil), addresses...))
	return nil
}

func (c *recordingBandwidthController) StartBandwidthMonitor(_ context.Context, ip netip.Addr, mac net.HardwareAddr) error {
	if c.monitorErr != nil {
		return c.monitorErr
	}
	if c.failMonitorIP.IsValid() && ip == c.failMonitorIP {
		return errors.New("monitor failed")
	}
	c.monitored = append(c.monitored, BandwidthTarget{IP: ip, MAC: append(net.HardwareAddr(nil), mac...)})
	return nil
}

func (c *recordingBandwidthController) StopBandwidthMonitor(_ context.Context, ip netip.Addr, mac net.HardwareAddr) error {
	c.stopped = append(c.stopped, BandwidthTarget{IP: ip, MAC: append(net.HardwareAddr(nil), mac...)})
	return nil
}

func (c *recordingBandwidthController) BandwidthTraffic(context.Context) ([]shaping.DeviceTrafficStats, error) {
	return []shaping.DeviceTrafficStats{{MAC: "02:00:00:00:00:20", UploadBytes: 42}}, nil
}

func (c *recordingBandwidthController) BandwidthForwarderStats(context.Context) (shaping.ForwarderStats, error) {
	return shaping.ForwarderStats{}, nil
}

func (c *recordingBandwidthController) SetBandwidthLimit(_ context.Context, ip netip.Addr, mac net.HardwareAddr, policy shaping.Policy) error {
	if c.setErr != nil {
		return c.setErr
	}
	c.mu.Lock()
	c.set = append(c.set, BandwidthTarget{IP: ip, MAC: append(net.HardwareAddr(nil), mac...), Policy: policy})
	c.mu.Unlock()
	return nil
}

func (c *recordingBandwidthController) RemoveBandwidthLimit(_ context.Context, ip netip.Addr, mac net.HardwareAddr) error {
	if c.remErr != nil {
		return c.remErr
	}
	c.mu.Lock()
	c.removed = append(c.removed, BandwidthTarget{IP: ip, MAC: append(net.HardwareAddr(nil), mac...)})
	c.mu.Unlock()
	return nil
}

func TestBandwidthServiceUsesLivePeerAndRecordedIdentityForRemoval(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	controller := &recordingBandwidthController{}
	service := NewBandwidthService(controller, registry, nil)
	policy := shaping.Policy{DownloadBitsPerSecond: 10_000_000, UploadBitsPerSecond: 2_000_000}
	if err := service.Set(context.Background(), target, policy); err != nil {
		t.Fatal(err)
	}
	if snapshot := service.Snapshot(); len(snapshot) != 1 || snapshot[0].Policy != policy.Effective() {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	// A later registry address change must not prevent recovery of the original
	// helper policy, which is keyed by the identity used when it was installed.
	_, _, err := registry.Observe(device.Observation{IP: netip.MustParseAddr("192.168.1.21"), MAC: target.MAC, SeenAt: time.Now().Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Remove(context.Background(), target.MAC); err != nil {
		t.Fatal(err)
	}
	if len(controller.removed) != 1 || controller.removed[0].IP != target.IP || len(service.Snapshot()) != 0 {
		t.Fatalf("removals = %#v, active = %#v", controller.removed, service.Snapshot())
	}
}

func TestBandwidthServiceInstallsAndReconcilesEveryDeviceAddress(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	ipv6 := netip.MustParseAddr("2001:db8:1::20")
	if _, _, err := registry.Observe(device.Observation{IP: ipv6, MAC: target.MAC, SeenAt: time.Now().Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	controller := &recordingDeviceBandwidthController{}
	service := NewBandwidthService(controller, registry, nil)
	if err := service.StartMonitoring(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if len(controller.monitoredAddresses) != 1 || len(controller.monitoredAddresses[0]) != 2 {
		t.Fatalf("installed addresses = %#v", controller.monitoredAddresses)
	}
	privacy := netip.MustParseAddr("2001:db8:1::99")
	current, _, err := registry.Observe(device.Observation{IP: privacy, MAC: target.MAC, SeenAt: time.Now().Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ReconcileDevice(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if len(controller.stoppedAddresses) != 1 || len(controller.monitoredAddresses) != 2 || len(controller.monitoredAddresses[1]) != 3 {
		t.Fatalf("reconciliation stop/start = %#v / %#v", controller.stoppedAddresses, controller.monitoredAddresses)
	}
}

func TestBandwidthServiceRejectsUnavailableUnsafeAndConflictingTargets(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	policy := shaping.Policy{UploadBitsPerSecond: 1_000_000}
	if err := NewBandwidthService(nil, registry, nil).Set(context.Background(), target, policy); !errors.Is(err, ErrBandwidthUnavailable) {
		t.Fatalf("unavailable error = %v", err)
	}
	service := NewBandwidthService(&recordingBandwidthController{}, registry, func(net.HardwareAddr) bool { return true })
	if err := service.Set(context.Background(), target, policy); !errors.Is(err, ErrBandwidthConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	target.IP = netip.MustParseAddr("192.168.1.99")
	if err := NewBandwidthService(&recordingBandwidthController{}, registry, nil).Set(context.Background(), target, policy); !errors.Is(err, ErrBandwidthTarget) {
		t.Fatalf("identity error = %v", err)
	}
}

func TestBandwidthServiceKeepsPolicyWhenRemovalFails(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	controller := &recordingBandwidthController{remErr: errors.New("restore failed")}
	service := NewBandwidthService(controller, registry, nil)
	if err := service.Set(context.Background(), target, shaping.Policy{UploadBitsPerSecond: 1_000_000}); err != nil {
		t.Fatal(err)
	}
	if err := service.Remove(context.Background(), target.MAC); err == nil {
		t.Fatal("expected removal failure")
	}
	if len(service.Snapshot()) != 1 {
		t.Fatal("failed recovery silently removed the active policy")
	}
}

func TestBandwidthServicePreservesMonitoringAcrossLimitLifecycle(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	controller := &recordingBandwidthController{}
	service := NewBandwidthService(controller, registry, nil)
	if err := service.StartMonitoring(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if err := service.Set(context.Background(), target, shaping.Policy{UploadBitsPerSecond: 1_000_000}); err != nil {
		t.Fatal(err)
	}
	if err := service.Remove(context.Background(), target.MAC); err != nil {
		t.Fatal(err)
	}
	if len(controller.monitored) != 2 || len(controller.removed) != 0 || len(service.MonitoringSnapshot()) != 1 {
		t.Fatalf("monitor transitions=%#v removals=%#v", controller.monitored, controller.removed)
	}
	traffic, err := service.Traffic(context.Background())
	if err != nil || len(traffic) != 1 || traffic[0].UploadBytes != 42 {
		t.Fatalf("traffic=%#v err=%v", traffic, err)
	}
	if err := service.StopMonitoring(context.Background(), target.MAC); err != nil || len(controller.stopped) != 1 {
		t.Fatalf("stop monitor: %v calls=%#v", err, controller.stopped)
	}
}

func TestBandwidthServiceReconcilesMonitoredIPv4Address(t *testing.T) {
	registry, target := bandwidthRegistry(t)
	controller := &recordingBandwidthController{}
	service := NewBandwidthService(controller, registry, nil)
	if err := service.StartMonitoring(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	newIP := netip.MustParseAddr("192.168.1.21")
	updated, _, err := registry.Observe(device.Observation{IP: newIP, MAC: target.MAC, SeenAt: time.Now().Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ReconcileDevice(context.Background(), updated); err != nil {
		t.Fatal(err)
	}
	snapshot := service.MonitoringSnapshot()
	if len(snapshot) != 1 || snapshot[0].IP != newIP || len(controller.stopped) != 1 || len(controller.monitored) != 2 {
		t.Fatalf("snapshot=%#v stopped=%#v monitored=%#v", snapshot, controller.stopped, controller.monitored)
	}
}

func TestRuntimeMonitorAllRollsBackNewRoutesOnFailure(t *testing.T) {
	registry := device.NewRegistry()
	for index, ipText := range []string{"192.168.1.20", "192.168.1.21"} {
		mac, _ := net.ParseMAC(fmt.Sprintf("02:00:00:00:00:%02x", index+20))
		if _, _, err := registry.Observe(device.Observation{IP: netip.MustParseAddr(ipText), MAC: mac, SeenAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	controller := &recordingBandwidthController{failMonitorIP: netip.MustParseAddr("192.168.1.21")}
	service := NewBandwidthService(controller, registry, nil)
	runtime := &Runtime{registry: registry, bandwidth: service, traffic: trafficmetrics.NewMonitor(service, time.Second, time.Hour)}
	if err := runtime.StartAllBandwidthMonitors(context.Background()); err == nil {
		t.Fatal("expected batch failure")
	}
	if len(service.MonitoringSnapshot()) != 0 || len(controller.stopped) != 1 {
		t.Fatalf("batch rollback failed: active=%#v stopped=%#v", service.MonitoringSnapshot(), controller.stopped)
	}
}

func bandwidthRegistry(t *testing.T) (*device.Registry, ControlTarget) {
	t.Helper()
	registry := device.NewRegistry()
	mac, _ := net.ParseMAC("02:00:00:00:00:20")
	ip := netip.MustParseAddr("192.168.1.20")
	if _, _, err := registry.Observe(device.Observation{IP: ip, MAC: mac, SeenAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	return registry, ControlTarget{IP: ip, MAC: mac}
}
