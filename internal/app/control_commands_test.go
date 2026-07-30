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

type failSecondControlAudit struct{ calls int }

func (a *failSecondControlAudit) Record(context.Context, ControlAuditEvent) error {
	a.calls++
	if a.calls == 2 {
		return errors.New("audit storage failed")
	}
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

type transactionalControlController struct {
	isolateCalls int
	failAt       int
	restored     []control.Endpoint
}

func (c *transactionalControlController) Isolate(_ context.Context, _ control.Endpoint) error {
	c.isolateCalls++
	if c.isolateCalls == c.failAt {
		return errors.New("send failed")
	}
	return nil
}

func (c *transactionalControlController) Restore(_ context.Context, target control.Endpoint) error {
	c.restored = append(c.restored, target)
	return nil
}

func (c *transactionalControlController) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (f *recordingControllerFactory) Prepare(context.Context, ControlRequest, ControlScope) (ControlControllerLease, error) {
	f.prepared++
	return ControlControllerLease{Controller: f.controller, Close: func() error { f.closed++; return nil }}, nil
}

func TestControlCommandsActivateAndAuditSupportedOperations(t *testing.T) {
	target := testControlTarget(t)
	operations := []struct {
		operation ControlOperation
		execute   func(*ControlCommands) error
	}{
		{ControlDisconnect, func(commands *ControlCommands) error { return commands.Disconnect(context.Background(), target) }},
		{ControlDisconnectAll, func(commands *ControlCommands) error { return commands.DisconnectAll(context.Background()) }},
		{ControlContinuous, func(commands *ControlCommands) error { return commands.StartContinuous(context.Background(), target) }},
	}
	for _, test := range operations {
		audit := &recordingControlAudit{}
		deps := testControlDependencies(t, audit)
		deps.Lifecycle = NewControlLifecycle(nil)
		commands := NewControlCommands(testActiveController(t, deps), deps)
		if err := test.execute(commands); err != nil {
			t.Fatalf("%s: %v", test.operation, err)
		}
		if len(deps.Lifecycle.Snapshot()) != 1 {
			t.Fatalf("%s active targets = %d", test.operation, len(deps.Lifecycle.Snapshot()))
		}
		if len(audit.events) != 2 || audit.events[0].Outcome != "requested" || audit.events[1].Outcome != "active" {
			t.Fatalf("%s audit events: %#v", test.operation, audit.events)
		}
		if err := deps.Lifecycle.RestoreAll(context.Background(), "test cleanup"); err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
}

func TestControlCommandsFilterIneligibleDevices(t *testing.T) {
	audit := &recordingControlAudit{}
	deps := testControlDependencies(t, audit)
	deps.Lifecycle = NewControlLifecycle(nil)
	deps.Devices = controlTestDevices{values: append(deps.Devices.Snapshot(),
		device.Device{IP: netip.MustParseAddr("192.168.1.30"), MAC: "02:00:00:00:00:30", Role: device.RolePeer, Online: false},
		device.Device{IP: deps.Scope.GatewayIP, MAC: "00:00:0c:00:00:01", Role: device.RoleGateway, Online: true},
	)}
	err := NewControlCommands(testActiveController(t, deps), deps).DisconnectAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(audit.events) != 2 || len(audit.events[0].Targets) != 1 || len(audit.events[1].Targets) != 1 {
		t.Fatalf("unexpected targets: %#v", audit.events)
	}
}

func TestControlCommandsRejectBandwidthLimitedTarget(t *testing.T) {
	blocked := errors.New("remove bandwidth limit first")
	deps := testControlDependencies(t, &recordingControlAudit{})
	deps.DisruptiveGuard = func(ControlTarget) error { return blocked }
	if err := NewControlCommands(testActiveController(t, deps), deps).Disconnect(context.Background(), testControlTarget(t)); !errors.Is(err, blocked) {
		t.Fatalf("disconnect error = %v", err)
	}
	if err := NewControlCommands(testActiveController(t, deps), deps).Restore(context.Background(), testControlTarget(t)); errors.Is(err, blocked) {
		t.Fatalf("recovery was incorrectly blocked: %v", err)
	}
}

func TestDisconnectSelectedUsesOnlyRequestedCurrentTargets(t *testing.T) {
	audit := &recordingControlAudit{}
	deps := testControlDependencies(t, audit)
	secondMAC, _ := net.ParseMAC("02:00:00:00:00:30")
	second := ControlTarget{IP: netip.MustParseAddr("192.168.1.30"), MAC: secondMAC}
	deps.Devices = controlTestDevices{values: append(deps.Devices.Snapshot(), device.Device{
		IP: second.IP, MAC: second.MAC.String(), Role: device.RolePeer, Online: true,
	})}
	deps.Lifecycle = NewControlLifecycle(nil)
	commands := NewControlCommands(testActiveController(t, deps), deps)
	if err := commands.DisconnectSelected(context.Background(), []ControlTarget{second}); err != nil {
		t.Fatal(err)
	}
	if len(audit.events) != 2 || len(audit.events[0].Targets) != 1 || audit.events[0].Targets[0].MAC.String() != second.MAC.String() {
		t.Fatalf("unexpected selected targets: %#v", audit.events)
	}
	if err := deps.Lifecycle.RestoreAll(context.Background(), "test cleanup"); err != nil {
		t.Fatal(err)
	}
}

func TestControlCommandsPrepareAndReleaseControllerBeforeExecutionBoundary(t *testing.T) {
	audit := &recordingControlAudit{}
	deps := testControlDependencies(t, audit)
	deps.Lifecycle = NewControlLifecycle(nil)
	factory := &recordingControllerFactory{controller: testActiveController(t, deps)}
	deps.ControllerFactory = factory
	err := NewControlCommands(nil, deps).Disconnect(context.Background(), testControlTarget(t))
	if err != nil {
		t.Fatalf("got %v", err)
	}
	if factory.prepared != 1 || factory.closed != 0 {
		t.Fatalf("factory prepared=%d closed=%d", factory.prepared, factory.closed)
	}
	if err := deps.Lifecycle.RestoreAll(context.Background(), "test cleanup"); err != nil {
		t.Fatal(err)
	}
	if factory.closed != 1 {
		t.Fatalf("factory closed=%d, want 1", factory.closed)
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

func TestDisconnectAllRollsBackPreviouslyIsolatedTargets(t *testing.T) {
	audit := &recordingControlAudit{}
	deps := testControlDependencies(t, audit)
	secondMAC, _ := net.ParseMAC("02:00:00:00:00:30")
	deps.Devices = controlTestDevices{values: append(deps.Devices.Snapshot(), device.Device{
		IP: netip.MustParseAddr("192.168.1.30"), MAC: secondMAC.String(), Role: device.RolePeer, Online: true,
	})}
	deps.Lifecycle = NewControlLifecycle(nil)
	controller := &transactionalControlController{failAt: 2}
	err := NewControlCommands(controller, deps).DisconnectAll(context.Background())
	if err == nil || len(controller.restored) != 1 {
		t.Fatalf("error=%v restored=%d", err, len(controller.restored))
	}
	if len(deps.Lifecycle.Snapshot()) != 0 {
		t.Fatalf("active targets = %d, want 0", len(deps.Lifecycle.Snapshot()))
	}
	if len(audit.events) != 2 || audit.events[1].Outcome != "rolled_back" {
		t.Fatalf("unexpected audit: %#v", audit.events)
	}
}

func TestActiveControlRestoresWhenOutcomeAuditFails(t *testing.T) {
	audit := &failSecondControlAudit{}
	deps := testControlDependencies(t, audit)
	deps.Lifecycle = NewControlLifecycle(nil)
	controller := &transactionalControlController{}
	err := NewControlCommands(controller, deps).Disconnect(context.Background(), testControlTarget(t))
	if err == nil {
		t.Fatal("expected outcome audit failure")
	}
	if len(controller.restored) != 1 || len(deps.Lifecycle.Snapshot()) != 0 {
		t.Fatalf("restored=%d active=%d", len(controller.restored), len(deps.Lifecycle.Snapshot()))
	}
}

func TestControlCommandsExtendExistingLifecycleSession(t *testing.T) {
	audit := &recordingControlAudit{}
	deps := testControlDependencies(t, audit)
	secondMAC, _ := net.ParseMAC("02:00:00:00:00:30")
	second := ControlTarget{IP: netip.MustParseAddr("192.168.1.30"), MAC: secondMAC}
	deps.Devices = controlTestDevices{values: append(deps.Devices.Snapshot(), device.Device{
		IP: second.IP, MAC: second.MAC.String(), Role: device.RolePeer, Online: true,
	})}
	deps.Lifecycle = NewControlLifecycle(nil)
	controller := &transactionalControlController{}
	if err := NewControlCommands(controller, deps).Disconnect(context.Background(), testControlTarget(t)); err != nil {
		t.Fatal(err)
	}
	if err := NewControlCommands(nil, deps).Disconnect(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if controller.isolateCalls != 2 || len(deps.Lifecycle.Snapshot()) != 2 {
		t.Fatalf("isolations=%d active=%d", controller.isolateCalls, len(deps.Lifecycle.Snapshot()))
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
