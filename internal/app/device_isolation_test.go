package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/control"
	"github.com/amdzy/NetWarden/internal/device"
)

type recordingIsolationBackend struct {
	isolated, restored [][]netip.Addr
	isolateErr         error
}

func (b *recordingIsolationBackend) SetDeviceIsolation(_ context.Context, addresses []netip.Addr, _ net.HardwareAddr, _ bool) error {
	b.isolated = append(b.isolated, append([]netip.Addr(nil), addresses...))
	return b.isolateErr
}
func (b *recordingIsolationBackend) RestoreDevice(_ context.Context, addresses []netip.Addr, _ net.HardwareAddr) error {
	b.restored = append(b.restored, append([]netip.Addr(nil), addresses...))
	return nil
}

func TestDeviceIsolationControllerUsesAllAddressesAndReconcilesPrivacyAddress(t *testing.T) {
	registry := device.NewRegistry()
	mac, _ := net.ParseMAC("02:00:00:00:00:20")
	now := time.Now().UTC()
	for _, address := range []netip.Addr{netip.MustParseAddr("192.168.1.20"), netip.MustParseAddr("2001:db8:1::20")} {
		if _, _, err := registry.Observe(device.Observation{IP: address, MAC: mac, SeenAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	backend := &recordingIsolationBackend{}
	controller := newDeviceIsolationController(backend, registry, true)
	endpoint := control.Endpoint{IP: netip.MustParseAddr("192.168.1.20"), MAC: mac}
	if err := controller.Isolate(context.Background(), endpoint); err != nil {
		t.Fatal(err)
	}
	if len(backend.isolated) != 1 || len(backend.isolated[0]) != 2 {
		t.Fatalf("isolated addresses = %#v", backend.isolated)
	}
	privacy := netip.MustParseAddr("2001:db8:1::99")
	current, _, err := registry.Observe(device.Observation{IP: privacy, MAC: mac, SeenAt: now.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Reconcile(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if len(backend.isolated) != 2 || len(backend.isolated[1]) != 3 {
		t.Fatalf("reconciled addresses = %#v", backend.isolated)
	}
	if err := controller.Restore(context.Background(), endpoint); err != nil {
		t.Fatal(err)
	}
	if len(backend.restored) != 1 || len(backend.restored[0]) != 3 {
		t.Fatalf("restored addresses = %#v", backend.restored)
	}
}

func TestDeviceIsolationControllerDoesNotRecordFailedActivation(t *testing.T) {
	registry := device.NewRegistry()
	mac, _ := net.ParseMAC("02:00:00:00:00:20")
	_, _, _ = registry.Observe(device.Observation{IP: netip.MustParseAddr("fe80::20"), MAC: mac})
	backend := &recordingIsolationBackend{isolateErr: errors.New("activation failed")}
	controller := newDeviceIsolationController(backend, registry, false)
	endpoint := control.Endpoint{IP: netip.MustParseAddr("fe80::20"), MAC: mac}
	if err := controller.Isolate(context.Background(), endpoint); !errors.Is(err, backend.isolateErr) {
		t.Fatalf("error = %v", err)
	}
	if len(controller.active) != 0 {
		t.Fatal("failed activation remained active")
	}
}
