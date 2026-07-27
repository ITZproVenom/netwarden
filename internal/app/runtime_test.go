package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/capture/pcapdriver"
	"github.com/amdzy/NetWarden/internal/device"
	networkgateway "github.com/amdzy/NetWarden/internal/network/gateway"
)

type fixedGateway struct{ route networkgateway.Route }

func (g fixedGateway) Discover(context.Context) (networkgateway.Route, error) { return g.route, nil }

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
	dependencies := Dependencies{
		Gateway: fixedGateway{route: networkgateway.Route{
			GatewayIP: netip.MustParseAddr("192.168.1.1"), InterfaceIP: netip.MustParseAddr("192.168.1.2"),
		}},
		Open: func(string) (capture.Driver, error) { return driver, nil },
		Resolve: func(context.Context, capture.Driver, net.HardwareAddr, netip.Addr, netip.Addr) (net.HardwareAddr, error) {
			return gatewayMAC, nil
		},
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
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if !driver.closed || driver.sends == 0 {
		t.Fatalf("driver closed=%v sends=%d", driver.closed, driver.sends)
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
}
