package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/shaping"
)

type recordingBandwidthController struct {
	mu      sync.Mutex
	set     []BandwidthTarget
	removed []BandwidthTarget
	setErr  error
	remErr  error
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
