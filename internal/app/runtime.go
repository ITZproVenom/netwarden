// Package app assembles and owns the NetWarden core services.
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/capture/pcapdriver"
	"github.com/amdzy/NetWarden/internal/core"
	"github.com/amdzy/NetWarden/internal/defense"
	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/discovery"
	"github.com/amdzy/NetWarden/internal/network"
	networkgateway "github.com/amdzy/NetWarden/internal/network/gateway"
)

type OpenDriver func(string) (capture.Driver, error)
type ResolveHardware func(context.Context, capture.Driver, net.HardwareAddr, netip.Addr, netip.Addr) (net.HardwareAddr, error)

type Dependencies struct {
	Gateway  networkgateway.Discoverer
	Open     OpenDriver
	Resolve  ResolveHardware
	Enricher core.Enricher
}

type Config struct {
	Interface        pcapdriver.Interface
	ScanInterval     time.Duration
	ProbeDelay       time.Duration
	MaximumHosts     int
	OfflineAfter     time.Duration
	LivenessCheck    time.Duration
	ConflictCooldown time.Duration
}

type Runtime struct {
	network  network.Context
	driver   capture.Driver
	registry *device.Registry
	service  *core.Service
	scanner  *discovery.Scanner
	monitor  *defense.Monitor
	config   Config

	mu      sync.Mutex
	cancel  context.CancelFunc
	running bool
	stopped bool
}

func DefaultDependencies() Dependencies {
	return Dependencies{
		Gateway: networkgateway.SystemDiscoverer{},
		Open: func(name string) (capture.Driver, error) {
			return pcapdriver.Open(name, pcapdriver.Config{Promiscuous: true, Filter: "arp"})
		},
		Resolve: discovery.ResolveARP,
	}
}

// Bootstrap verifies the selected adapter against the OS default route and
// resolves the gateway identity before starting any background work.
func Bootstrap(ctx context.Context, dependencies Dependencies, config Config) (*Runtime, error) {
	if dependencies.Gateway == nil || dependencies.Open == nil || dependencies.Resolve == nil {
		return nil, errors.New("gateway discovery, capture factory, and address resolver are required")
	}
	if config.Interface.Name == "" || len(config.Interface.MAC) != 6 {
		return nil, errors.New("a capture interface with an Ethernet MAC is required")
	}
	applyRuntimeDefaults(&config)

	route, err := dependencies.Gateway.Discover(ctx)
	if err != nil {
		return nil, err
	}
	prefix, err := prefixForRoute(config.Interface.Prefixes, route)
	if err != nil {
		return nil, fmt.Errorf("selected interface %q: %w", config.Interface.Name, err)
	}
	driver, err := dependencies.Open(config.Interface.Name)
	if err != nil {
		return nil, err
	}
	gatewayMAC, err := dependencies.Resolve(ctx, driver, config.Interface.MAC, route.InterfaceIP, route.GatewayIP)
	if err != nil {
		driver.Close()
		return nil, fmt.Errorf("resolve default gateway identity: %w", err)
	}

	networkContext, err := network.NewContext(
		config.Interface.Name, config.Interface.SystemName, prefix,
		network.Endpoint{IP: route.InterfaceIP, MAC: config.Interface.MAC},
		network.Endpoint{IP: route.GatewayIP, MAC: gatewayMAC},
	)
	if err != nil {
		driver.Close()
		return nil, err
	}

	registry := device.NewRegistry()
	now := time.Now().UTC()
	_, _, err = registry.Observe(device.Observation{IP: networkContext.Local.IP, MAC: networkContext.Local.MAC, SeenAt: now})
	if err != nil {
		driver.Close()
		return nil, err
	}
	registry.SetRole(networkContext.Local.MAC, device.RoleLocal)
	_, _, err = registry.Observe(device.Observation{IP: networkContext.Gateway.IP, MAC: networkContext.Gateway.MAC, SeenAt: now})
	if err != nil {
		driver.Close()
		return nil, err
	}
	registry.SetRole(networkContext.Gateway.MAC, device.RoleGateway)
	monitor := defense.NewMonitor(networkContext.Gateway.IP, networkContext.Gateway.MAC, config.ConflictCooldown)
	options := []core.Option{core.WithARPObserver(monitor)}
	if dependencies.Enricher != nil {
		options = append(options, core.WithEnricher(dependencies.Enricher))
	}
	service := core.NewService(driver, registry, config.OfflineAfter, config.LivenessCheck, options...)
	prober := discovery.NewARPProber(driver, networkContext.Local.MAC, networkContext.Local.IP)
	scanner := discovery.NewScanner(prober, config.MaximumHosts, config.ProbeDelay)
	return &Runtime{
		network: networkContext, driver: driver, registry: registry,
		service: service, scanner: scanner, monitor: monitor, config: config,
	}, nil
}

func (r *Runtime) Network() network.Context              { return r.network.Clone() }
func (r *Runtime) Devices() []device.Device              { return r.registry.Snapshot() }
func (r *Runtime) DeviceEvents() <-chan core.Event       { return r.service.Events() }
func (r *Runtime) IntegrityEvents() <-chan defense.Event { return r.monitor.Events() }

// Run owns both background services and closes packet I/O only after both have
// observed cancellation. A Runtime is intentionally one-shot.
func (r *Runtime) Run(ctx context.Context) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return errors.New("runtime is already running")
	}
	if r.stopped {
		r.mu.Unlock()
		return errors.New("runtime has already stopped")
	}
	workerCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.running = true
	r.mu.Unlock()

	serviceResult := make(chan error, 1)
	scannerResult := make(chan error, 1)
	go func() { serviceResult <- r.service.Run(workerCtx) }()
	go func() { scannerResult <- r.scanner.Run(workerCtx, r.network.Prefix, r.config.ScanInterval) }()

	var first error
	select {
	case first = <-serviceResult:
		cancel()
		second := <-scannerResult
		first = meaningfulError(first, second, ctx.Err())
	case first = <-scannerResult:
		cancel()
		second := <-serviceResult
		first = meaningfulError(first, second, ctx.Err())
	case <-ctx.Done():
		cancel()
		serviceErr := <-serviceResult
		scannerErr := <-scannerResult
		first = meaningfulError(serviceErr, scannerErr, ctx.Err())
	}
	closeErr := r.service.Close()

	r.mu.Lock()
	r.running = false
	r.stopped = true
	r.cancel = nil
	r.mu.Unlock()
	return errors.Join(first, closeErr)
}

// Close requests shutdown. When Run was never called, it closes the driver
// directly; otherwise Run retains responsibility for ordered cleanup.
func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return nil
	}
	if r.running {
		r.cancel()
		return nil
	}
	r.stopped = true
	return r.driver.Close()
}

func prefixForRoute(prefixes []netip.Prefix, route networkgateway.Route) (netip.Prefix, error) {
	for _, prefix := range prefixes {
		if prefix.Addr() == route.InterfaceIP && prefix.Masked().Contains(route.GatewayIP) {
			return netip.PrefixFrom(route.InterfaceIP, prefix.Bits()), nil
		}
	}
	return netip.Prefix{}, fmt.Errorf("default route %s via local address %s does not use this interface", route.GatewayIP, route.InterfaceIP)
}

func applyRuntimeDefaults(config *Config) {
	if config.ScanInterval <= 0 {
		config.ScanInterval = 10 * time.Second
	}
	if config.ProbeDelay < 0 {
		config.ProbeDelay = 0
	}
	if config.MaximumHosts <= 0 {
		config.MaximumHosts = 4094
	}
	if config.OfflineAfter <= 0 {
		config.OfflineAfter = time.Minute
	}
	if config.LivenessCheck <= 0 {
		config.LivenessCheck = 10 * time.Second
	}
	if config.ConflictCooldown <= 0 {
		config.ConflictCooldown = 5 * time.Second
	}
}

func meaningfulError(errorsToCheck ...error) error {
	for _, err := range errorsToCheck {
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	}
	for _, err := range errorsToCheck {
		if err != nil {
			return err
		}
	}
	return nil
}
