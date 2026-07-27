package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/capture/pcapdriver"
	appconfig "github.com/amdzy/NetWarden/internal/config"
	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/history"
	"github.com/amdzy/NetWarden/internal/metadata"
	networkgateway "github.com/amdzy/NetWarden/internal/network/gateway"
)

type fixedGateway struct{ route networkgateway.Route }

func (g fixedGateway) Discover(context.Context) (networkgateway.Route, error) { return g.route, nil }

type changingGateway struct {
	mu     sync.Mutex
	routes []networkgateway.Route
	calls  int
}

func (g *changingGateway) Discover(context.Context) (networkgateway.Route, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	index := g.calls
	if index >= len(g.routes) {
		index = len(g.routes) - 1
	}
	g.calls++
	return g.routes[index], nil
}

type runtimeDriver struct {
	mu     sync.Mutex
	sends  int
	closed bool
}

func (d *runtimeDriver) Run(ctx context.Context, _ func(capture.Frame) error) error {
	<-ctx.Done()
	return ctx.Err()
}
func (d *runtimeDriver) Send(ctx context.Context, _ []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	d.sends++
	d.mu.Unlock()
	return nil
}
func (d *runtimeDriver) Close() error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	return nil
}

func TestBootstrapAssignsNetworkRolesAndRuntimeStopsCleanly(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	gatewayMAC, _ := net.ParseMAC("00:00:0c:00:00:01")
	driver := &runtimeDriver{}
	resolver, err := metadata.NewResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	settings := appconfig.NewStore(filepath.Join(t.TempDir(), "config.json"))
	historyStore := history.NewStore(settings.Path() + ".history.json")
	dependencies := Dependencies{
		Gateway: fixedGateway{route: networkgateway.Route{
			GatewayIP: netip.MustParseAddr("192.168.1.1"), InterfaceIP: netip.MustParseAddr("192.168.1.2"),
		}},
		Open: func(string) (capture.Driver, error) { return driver, nil },
		Resolve: func(context.Context, capture.Driver, net.HardwareAddr, netip.Addr, netip.Addr) (net.HardwareAddr, error) {
			return gatewayMAC, nil
		},
		Metadata: resolver,
		Settings: settings,
		History:  historyStore,
	}
	runtime, err := Bootstrap(context.Background(), dependencies, Config{
		Interface: pcapdriver.Interface{
			Name: "pcap0", SystemName: "en0", MAC: localMAC,
			Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.2/30")},
		},
		ScanInterval: time.Hour,
		ProbeDelay:   0,
		MaximumHosts: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	roles := make(map[device.Role]bool)
	for _, snapshot := range runtime.Devices() {
		roles[snapshot.Role] = true
	}
	if !roles[device.RoleLocal] || !roles[device.RoleGateway] {
		t.Fatalf("missing roles in %#v", runtime.Devices())
	}
	status := runtime.Status()
	if status.Running || status.Stopped || status.DeviceCount != 2 || !status.PeriodicScanEnabled {
		t.Fatalf("unexpected bootstrap status: %#v", status)
	}
	runtime.SetPeriodicScanEnabled(false)
	if runtime.Status().PeriodicScanEnabled {
		t.Fatal("periodic scan control was not applied")
	}
	if err := runtime.ScanNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	peerMAC, _ := net.ParseMAC("02:00:00:00:00:20")
	_, _, _ = runtime.registry.Observe(device.Observation{
		IP: netip.MustParseAddr("192.168.1.3"), MAC: peerMAC, SeenAt: time.Now().UTC(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	if err := runtime.SetNickname(localMAC, "This Mac"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-func() <-chan struct{} {
		found := make(chan struct{})
		go func() {
			for event := range runtime.Events() {
				if event.Kind == EventDeviceMetadataChanged && event.Device != nil && event.Device.Name == "This Mac" {
					close(found)
					return
				}
			}
		}()
		return found
	}():
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for live metadata event")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if !driver.closed || driver.sends == 0 {
		t.Fatalf("driver closed=%v sends=%d", driver.closed, driver.sends)
	}
	persisted, err := historyStore.Load()
	if err != nil {
		t.Fatal(err)
	}
	foundPeer := false
	for _, snapshot := range persisted.Devices {
		foundPeer = foundPeer || snapshot.MAC == peerMAC.String()
	}
	if !foundPeer {
		t.Fatalf("peer was not persisted: %#v", persisted.Devices)
	}
}

func TestBootstrapRejectsInterfaceOutsideDefaultRoute(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	driver := &runtimeDriver{}
	_, err := Bootstrap(context.Background(), Dependencies{
		Gateway: fixedGateway{route: networkgateway.Route{
			GatewayIP: netip.MustParseAddr("10.0.0.1"), InterfaceIP: netip.MustParseAddr("10.0.0.2"),
		}},
		Open: func(string) (capture.Driver, error) { return driver, nil },
		Resolve: func(context.Context, capture.Driver, net.HardwareAddr, netip.Addr, netip.Addr) (net.HardwareAddr, error) {
			return nil, errors.New("should not be called")
		},
	}, Config{Interface: pcapdriver.Interface{
		Name: "pcap0", MAC: localMAC,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.2/24")},
	}})
	if err == nil {
		t.Fatal("expected route mismatch")
	}
	var runtimeError *Error
	if !errors.As(err, &runtimeError) || runtimeError.Stage != StageGatewayRoute {
		t.Fatalf("unexpected typed error: %v", err)
	}
}

func TestRuntimeStopsWhenDefaultRouteChanges(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	gatewayMAC, _ := net.ParseMAC("00:00:0c:00:00:01")
	initial := networkgateway.Route{
		GatewayIP: netip.MustParseAddr("192.168.1.1"), InterfaceIP: netip.MustParseAddr("192.168.1.2"),
	}
	discoverer := &changingGateway{routes: []networkgateway.Route{
		initial,
		{GatewayIP: netip.MustParseAddr("192.168.1.5"), InterfaceIP: netip.MustParseAddr("192.168.1.2")},
	}}
	runtime, err := Bootstrap(context.Background(), Dependencies{
		Gateway: discoverer,
		Open:    func(string) (capture.Driver, error) { return &runtimeDriver{}, nil },
		Resolve: func(context.Context, capture.Driver, net.HardwareAddr, netip.Addr, netip.Addr) (net.HardwareAddr, error) {
			return gatewayMAC, nil
		},
	}, Config{
		Interface: pcapdriver.Interface{
			Name: "pcap0", MAC: localMAC,
			Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.2/24")},
		},
		NetworkCheck: time.Millisecond,
		ScanInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = runtime.Run(context.Background())
	if !errors.Is(err, ErrNetworkChanged) {
		t.Fatalf("got %v, want ErrNetworkChanged", err)
	}
	var runtimeError *Error
	if !errors.As(err, &runtimeError) || runtimeError.Stage != StageNetworkChange {
		t.Fatalf("unexpected typed error: %v", err)
	}
}
