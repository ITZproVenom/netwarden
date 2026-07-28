package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/amdzy/NetWarden/internal/control"
	"github.com/amdzy/NetWarden/internal/device"
)

type controlTestDevices struct{ values []device.Device }

func (d controlTestDevices) Snapshot() []device.Device {
	return append([]device.Device(nil), d.values...)
}

type recordingControlAudit struct{ events []ControlAuditEvent }

func (a *recordingControlAudit) Record(_ context.Context, event ControlAuditEvent) error {
	a.events = append(a.events, event)
	return nil
}

type recoverySender struct{ sends int }

func (s *recoverySender) Send(ctx context.Context, _ []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.sends++
	return nil
}

type recordingControllerFactory struct {
	controller *control.Controller
	prepared   int
	closed     int
}

func (f *recordingControllerFactory) Prepare(context.Context, ControlRequest, ControlScope) (ControlControllerLease, error) {
	f.prepared++
	return ControlControllerLease{Controller: f.controller, Close: func() error { f.closed++; return nil }}, nil
}

func TestControlCommandsReachAuditedNotImplementedBoundary(t *testing.T) {
	target := testControlTarget(t)
	audit := &recordingControlAudit{}
	deps := testControlDependencies(t, audit)
	commands := NewControlCommands(testActiveController(t, deps), deps)
	for _, execute := range []func() error{
		func() error { return commands.Disconnect(context.Background(), target) },
		func() error { return commands.DisconnectAll(context.Background()) },
		func() error { return commands.StartContinuous(context.Background(), target) },
	} {
		if err := execute(); !errors.Is(err, ErrActiveControlNotImplemented) {
			t.Fatalf("got %v, want ErrActiveControlNotImplemented", err)
		}
	}
	if len(audit.events) != 3 {
		t.Fatalf("audit events = %d, want 3", len(audit.events))
	}
	for _, event := range audit.events {
		if event.Outcome != "ready_not_implemented" || len(event.Targets) != 1 {
			t.Fatalf("unexpected audit event: %#v", event)
		}
	}
}

func TestControlCommandsFilterIneligibleDevices(t *testing.T) {
	audit := &recordingControlAudit{}
	deps := testControlDependencies(t, audit)
	deps.Devices = controlTestDevices{values: append(deps.Devices.Snapshot(),
		device.Device{IP: netip.MustParseAddr("192.168.1.30"), MAC: "02:00:00:00:00:30", Role: device.RolePeer, Online: false},
		device.Device{IP: deps.Scope.GatewayIP, MAC: "00:00:0c:00:00:01", Role: device.RoleGateway, Online: true},
	)}
	err := NewControlCommands(testActiveController(t, deps), deps).DisconnectAll(context.Background())
	if !errors.Is(err, ErrActiveControlNotImplemented) {
		t.Fatal(err)
	}
	if len(audit.events) != 1 || len(audit.events[0].Targets) != 1 {
		t.Fatalf("unexpected targets: %#v", audit.events)
	}
}

func TestControlCommandsPrepareAndReleaseControllerBeforeExecutionBoundary(t *testing.T) {
	audit := &recordingControlAudit{}
	deps := testControlDependencies(t, audit)
	factory := &recordingControllerFactory{controller: testActiveController(t, deps)}
	deps.ControllerFactory = factory
	err := NewControlCommands(nil, deps).Disconnect(context.Background(), testControlTarget(t))
	if !errors.Is(err, ErrActiveControlNotImplemented) {
		t.Fatalf("got %v", err)
	}
	if factory.prepared != 1 || factory.closed != 1 {
		t.Fatalf("factory prepared=%d closed=%d", factory.prepared, factory.closed)
	}
}

func TestRecoveryBypassesDisruptiveAuthorizationAndCallsRestore(t *testing.T) {
	audit := &recordingControlAudit{}
	deps := testControlDependencies(t, audit)
	sender := &recoverySender{}
	controller, err := control.NewController(sender,
		control.Endpoint{IP: deps.Scope.LocalIP, MAC: deps.Scope.LocalMAC},
		control.Endpoint{IP: deps.Scope.GatewayIP, MAC: deps.Scope.GatewayMAC},
		deps.Scope.Prefix, control.Options{RestorationCount: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	commands := NewControlCommands(controller, deps)
	if err := commands.Restore(context.Background(), testControlTarget(t)); err != nil {
		t.Fatal(err)
	}
	if sender.sends != 1 {
		t.Fatalf("restore sends = %d, want 1", sender.sends)
	}
	if len(audit.events) != 1 || audit.events[0].Outcome != "restored" || audit.events[0].Operation != ControlRestore {
		t.Fatalf("unexpected audit: %#v", audit.events)
	}
}

func TestRuntimeControlCommandsRestoreThroughOwnedLifecycle(t *testing.T) {
	target := testControlTarget(t)
	audit := &recordingControlAudit{}
	deps := testControlDependencies(t, audit)
	controller := &lifecycleController{run: make(chan struct{})}
	lifecycle := NewControlLifecycle(nil)
	if err := lifecycle.AdoptActive(ControlControllerLease{Controller: controller}, ControlDisconnect, []ControlTarget{target}, false); err != nil {
		t.Fatal(err)
	}
	deps.Lifecycle = lifecycle
	if err := NewControlCommands(nil, deps).Restore(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if len(controller.restored) != 1 || len(lifecycle.Snapshot()) != 0 {
		t.Fatalf("restored=%d active=%d", len(controller.restored), len(lifecycle.Snapshot()))
	}
	if len(audit.events) != 1 || audit.events[0].Operation != ControlRestore || audit.events[0].Outcome != "restored" {
		t.Fatalf("unexpected audit: %#v", audit.events)
	}
}

func testControlDependencies(t *testing.T, audit ControlAuditor) ControlDependencies {
	t.Helper()
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	gatewayMAC, _ := net.ParseMAC("00:00:0c:00:00:01")
	target := testControlTarget(t)
	return ControlDependencies{
		Devices: controlTestDevices{values: []device.Device{{IP: target.IP, MAC: target.MAC.String(), Role: device.RolePeer, Online: true}}},
		Scope:   ControlScope{Prefix: netip.MustParsePrefix("192.168.1.10/24"), LocalIP: netip.MustParseAddr("192.168.1.10"), LocalMAC: localMAC, GatewayIP: netip.MustParseAddr("192.168.1.1"), GatewayMAC: gatewayMAC},
		Auditor: audit,
	}
}

func testControlTarget(t *testing.T) ControlTarget {
	t.Helper()
	mac, _ := net.ParseMAC("02:00:00:00:00:20")
	return ControlTarget{IP: netip.MustParseAddr("192.168.1.20"), MAC: mac}
}

func testActiveController(t *testing.T, deps ControlDependencies) *control.Controller {
	t.Helper()
	controller, err := control.NewController(&recoverySender{},
		control.Endpoint{IP: deps.Scope.LocalIP, MAC: deps.Scope.LocalMAC},
		control.Endpoint{IP: deps.Scope.GatewayIP, MAC: deps.Scope.GatewayMAC},
		deps.Scope.Prefix, control.Options{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return controller
}
