// Package app assembles and owns the NetWarden core services.
package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/capture/pcapdriver"
	appconfig "github.com/amdzy/NetWarden/internal/config"
	"github.com/amdzy/NetWarden/internal/control"
	"github.com/amdzy/NetWarden/internal/core"
	"github.com/amdzy/NetWarden/internal/defense"
	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/discovery"
	"github.com/amdzy/NetWarden/internal/history"
	"github.com/amdzy/NetWarden/internal/network"
	networkgateway "github.com/amdzy/NetWarden/internal/network/gateway"
	"github.com/amdzy/NetWarden/internal/shaping"
	trafficmetrics "github.com/amdzy/NetWarden/internal/traffic"
)

type OpenDriver func(string) (capture.Driver, error)
type ResolveHardware func(context.Context, capture.Driver, net.HardwareAddr, netip.Addr, netip.Addr) (net.HardwareAddr, error)

type MetadataEditor interface {
	core.Enricher
	SetNickname(net.HardwareAddr, string)
	RemoveNickname(net.HardwareAddr)
}

type metadataRefreshBinder interface {
	SetRefresh(func(string))
}

type Dependencies struct {
	Gateway  networkgateway.Discoverer
	Open     OpenDriver
	Resolve  ResolveHardware
	Enricher core.Enricher
	Metadata MetadataEditor
	Settings *appconfig.Store
	History  *history.Store
}

type Config struct {
	Interface            pcapdriver.Interface
	ScanInterval         time.Duration
	ProbeDelay           time.Duration
	MaximumHosts         int
	OfflineAfter         time.Duration
	LivenessCheck        time.Duration
	ConflictCooldown     time.Duration
	NetworkCheck         time.Duration
	DeviceRetention      time.Duration
	PinnedGatewayMAC     net.HardwareAddr
	HistoryRetention     time.Duration
	IPv6AddressRetention time.Duration
}

type Status struct {
	Running                      bool
	Stopped                      bool
	Scanning                     bool
	PeriodicScanEnabled          bool
	DeviceCount                  int
	DroppedEvents                uint64
	LastPersistenceError         string
	Generation                   uint64
	RestartCount                 uint64
	Rebuilding                   bool
	LastRestartReason            string
	SupervisorDroppedEvents      uint64
	ActiveControlTargets         int
	ContinuousControl            bool
	BandwidthAvailable           bool
	ActiveBandwidthLimits        int
	BandwidthMonitoringAvailable bool
	ActiveBandwidthMonitors      int
	IPv6Available                bool
	IPv6RouterIP                 string
	IPv6RouterMAC                string
	IPv6PrefixCount              int
	IPv6RouterConflicts          int
}

type Runtime struct {
	network  network.Context
	driver   capture.Driver
	registry *device.Registry
	service  *core.Service
	scanner  *discovery.Scanner
	monitor  *defense.Monitor
	ipv6     *discovery.IPv6RouterTracker
	metadata MetadataEditor
	settings *appconfig.Store
	history  *history.Store
	config   Config
	events   chan Event
	gateway  networkgateway.Discoverer
	route    networkgateway.Route

	mu         sync.Mutex
	cancel     context.CancelFunc
	running    bool
	stopped    bool
	dropped    atomic.Uint64
	persist    chan struct{}
	persistErr error
	done       chan struct{}
	doneOnce   sync.Once
	control    *ControlLifecycle
	bandwidth  *BandwidthService
	traffic    *trafficmetrics.Monitor
}

func DefaultDependencies() Dependencies {
	return Dependencies{
		Gateway: networkgateway.SystemDiscoverer{},
		Open: func(name string) (capture.Driver, error) {
			return pcapdriver.Open(name, pcapdriver.Config{Promiscuous: true, Filter: "arp or icmp6"})
		},
		Resolve: discovery.ResolveARP,
	}
}

// Bootstrap verifies the selected adapter against the OS default route and
// resolves the gateway identity before starting any background work.
func Bootstrap(ctx context.Context, dependencies Dependencies, config Config) (*Runtime, error) {
	if dependencies.Gateway == nil || dependencies.Open == nil || dependencies.Resolve == nil {
		return nil, stageError(StageConfiguration, errors.New("gateway discovery, capture factory, and address resolver are required"))
	}
	if config.Interface.Name == "" || len(config.Interface.MAC) != 6 {
		return nil, stageError(StageConfiguration, errors.New("a capture interface with an Ethernet MAC is required"))
	}
	applyRuntimeDefaults(&config)

	route, err := dependencies.Gateway.Discover(ctx)
	if err != nil {
		return nil, stageError(StageGatewayRoute, err)
	}
	prefix, err := prefixForRoute(config.Interface.Prefixes, route)
	if err != nil {
		return nil, stageError(StageGatewayRoute, fmt.Errorf("selected interface %q: %w", config.Interface.Name, err))
	}
	driver, err := dependencies.Open(config.Interface.Name)
	if err != nil {
		return nil, stageError(StageCaptureOpen, err)
	}
	gatewayMAC, err := dependencies.Resolve(ctx, driver, config.Interface.MAC, route.InterfaceIP, route.GatewayIP)
	if err != nil {
		driver.Close()
		return nil, stageError(StageGatewayIdentity, fmt.Errorf("resolve default gateway identity: %w", err))
	}
	baselineMAC := gatewayMAC
	pinned := len(config.PinnedGatewayMAC) != 0
	if pinned {
		if len(config.PinnedGatewayMAC) != 6 {
			driver.Close()
			return nil, stageError(StageConfiguration, errors.New("pinned gateway MAC must contain 6 bytes"))
		}
		baselineMAC = append(net.HardwareAddr(nil), config.PinnedGatewayMAC...)
	}

	networkContext, err := network.NewContext(
		config.Interface.Name, config.Interface.SystemName, prefix,
		network.Endpoint{IP: route.InterfaceIP, MAC: config.Interface.MAC},
		network.Endpoint{IP: route.GatewayIP, MAC: baselineMAC},
	)
	if err != nil {
		driver.Close()
		return nil, stageError(StageConfiguration, err)
	}

	registry := device.NewRegistry()
	var durableHistory history.Snapshot
	if dependencies.History != nil {
		snapshot, loadErr := dependencies.History.Load()
		if loadErr != nil {
			driver.Close()
			return nil, stageError(StagePersistence, loadErr)
		}
		durableHistory = snapshot
		registry.Restore(snapshot.Devices)
	}
	now := time.Now().UTC()
	_, _, err = registry.Observe(device.Observation{IP: networkContext.Local.IP, MAC: networkContext.Local.MAC, SeenAt: now})
	if err != nil {
		driver.Close()
		return nil, stageError(StageConfiguration, err)
	}
	registry.SetRole(networkContext.Local.MAC, device.RoleLocal)
	_, _, err = registry.Observe(device.Observation{IP: networkContext.Gateway.IP, MAC: networkContext.Gateway.MAC, SeenAt: now})
	if err != nil {
		driver.Close()
		return nil, stageError(StageConfiguration, err)
	}
	registry.SetRole(networkContext.Gateway.MAC, device.RoleGateway)
	monitor := defense.NewMonitor(networkContext.Gateway.IP, networkContext.Gateway.MAC, config.ConflictCooldown)
	if pinned {
		monitor = defense.NewPinnedMonitor(networkContext.Gateway.IP, networkContext.Gateway.MAC, config.ConflictCooldown)
	}
	monitor.RestoreHistory(durableHistory.Conflicts)
	localIPv6 := make([]netip.Addr, 0)
	for _, candidate := range config.Interface.Prefixes {
		if candidate.Addr().Is6() {
			localIPv6 = append(localIPv6, candidate.Addr())
		}
	}
	ipv6 := discovery.NewIPv6RouterTracker(localIPv6)
	ipv6.RestoreState(durableHistory.IPv6Routers)
	options := []core.Option{core.WithARPObserver(monitor), core.WithNDPObserver(ipv6), core.WithRemovalAfter(config.DeviceRetention), core.WithIPv6AddressRetention(config.IPv6AddressRetention), core.WithIgnoredSenderMAC(config.Interface.MAC)}
	if dependencies.Metadata != nil {
		options = append(options, core.WithEnricher(dependencies.Metadata))
	} else if dependencies.Enricher != nil {
		options = append(options, core.WithEnricher(dependencies.Enricher))
	}
	service := core.NewService(driver, registry, config.OfflineAfter, config.LivenessCheck, options...)
	if binder, ok := dependencies.Metadata.(metadataRefreshBinder); ok {
		binder.SetRefresh(func(mac string) { service.RefreshMetadata(mac) })
	}
	prober := discovery.NewARPProber(driver, networkContext.Local.MAC, networkContext.Local.IP)
	scanner := discovery.NewScanner(prober, config.MaximumHosts, config.ProbeDelay)
	runtime := &Runtime{
		network: networkContext, driver: driver, registry: registry,
		service: service, scanner: scanner, monitor: monitor, ipv6: ipv6, config: config,
		metadata: dependencies.Metadata, settings: dependencies.Settings,
		events: make(chan Event, 128), gateway: dependencies.Gateway, route: route,
		history: dependencies.History, persist: make(chan struct{}, 1),
		done: make(chan struct{}),
	}
	runtime.control = NewControlLifecycle(runtime.publish)
	controller, _ := driver.(BandwidthController)
	runtime.bandwidth = NewBandwidthService(controller, registry, func(mac net.HardwareAddr) bool {
		for _, target := range runtime.control.Snapshot() {
			if target.MAC.String() == mac.String() {
				return true
			}
		}
		return false
	})
	runtime.traffic = trafficmetrics.NewMonitor(runtime.bandwidth, time.Second, time.Hour)
	runtime.traffic.RestoreState(durableHistory.Traffic, now)
	scanner.SetObserver(runtime.handleScanEvent)
	if pinned && gatewayMAC.String() != baselineMAC.String() {
		monitor.ObserveGatewayClaim(gatewayMAC, now)
	}
	return runtime, nil
}

func (r *Runtime) Network() network.Context { return r.network.Clone() }
func (r *Runtime) Devices() []device.Device { return r.registry.Snapshot() }
func (r *Runtime) Events() <-chan Event     { return r.events }
func (r *Runtime) Done() <-chan struct{}    { return r.done }
func (r *Runtime) DroppedEvents() uint64 {
	return r.dropped.Load() + r.service.DroppedEvents() + r.monitor.DroppedEvents() + r.ipv6.DroppedEvents()
}

func (r *Runtime) Status() Status {
	r.mu.Lock()
	running, stopped, persistErr := r.running, r.stopped, r.persistErr
	r.mu.Unlock()
	ipv6 := r.ipv6.Snapshot(time.Now().UTC())
	status := Status{
		Running: running, Stopped: stopped, Scanning: r.scanner.Scanning(),
		PeriodicScanEnabled: r.scanner.PeriodicEnabled(), DeviceCount: len(r.Devices()),
		DroppedEvents: r.DroppedEvents(), LastPersistenceError: errorText(persistErr),
		ActiveControlTargets: len(r.control.Snapshot()), ContinuousControl: r.control.ContinuousRunning(),
		BandwidthAvailable: r.bandwidth.Available(), ActiveBandwidthLimits: len(r.bandwidth.Snapshot()),
		BandwidthMonitoringAvailable: r.bandwidth.MonitoringAvailable(), ActiveBandwidthMonitors: len(r.bandwidth.MonitoringSnapshot()),
		IPv6Available: len(ipv6.LocalAddresses) > 0,
	}
	status.IPv6RouterConflicts = ipv6.ConflictCount
	if ipv6.DefaultRouter != nil {
		status.IPv6RouterIP, status.IPv6RouterMAC = ipv6.DefaultRouter.IP.String(), ipv6.DefaultRouter.MAC
		status.IPv6PrefixCount = len(ipv6.DefaultRouter.Prefixes)
	}
	return status
}

func (r *Runtime) IPv6Network() discovery.IPv6Context { return r.ipv6.Snapshot(time.Now().UTC()) }

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (r *Runtime) ScanNow(ctx context.Context) error {
	return r.scanner.Scan(ctx, r.network.Prefix)
}

func (r *Runtime) SetPeriodicScanEnabled(enabled bool) { r.scanner.SetPeriodicEnabled(enabled) }

func (r *Runtime) ConflictHistory() []defense.Conflict { return r.monitor.History() }
func (r *Runtime) ControlTargets() []ControlTarget     { return r.control.Snapshot() }

func (r *Runtime) BandwidthLimits() []BandwidthTarget   { return r.bandwidth.Snapshot() }
func (r *Runtime) BandwidthMonitors() []BandwidthTarget { return r.bandwidth.MonitoringSnapshot() }

func (r *Runtime) SetBandwidthLimit(ctx context.Context, target ControlTarget, policy shaping.Policy) error {
	return r.bandwidth.Set(ctx, target, policy)
}

func (r *Runtime) RemoveBandwidthLimit(ctx context.Context, mac net.HardwareAddr) error {
	return r.bandwidth.Remove(ctx, mac)
}

func (r *Runtime) ClearBandwidthLimits(ctx context.Context) error { return r.bandwidth.Clear(ctx) }

func (r *Runtime) StartBandwidthMonitor(ctx context.Context, target ControlTarget) error {
	if err := r.bandwidth.StartMonitoring(ctx, target); err != nil {
		return err
	}
	r.traffic.StartSession(target.MAC.String(), time.Now().UTC())
	return nil
}

func (r *Runtime) StopBandwidthMonitor(ctx context.Context, mac net.HardwareAddr) error {
	if err := r.bandwidth.StopMonitoring(ctx, mac); err != nil {
		return err
	}
	r.traffic.StopSession(mac.String(), time.Now().UTC())
	return nil
}

func (r *Runtime) BandwidthTraffic(ctx context.Context) ([]shaping.DeviceTrafficStats, error) {
	return r.bandwidth.Traffic(ctx)
}

func (r *Runtime) BandwidthMeasurements() ([]trafficmetrics.DeviceSnapshot, error) {
	return r.traffic.Snapshot()
}

type BandwidthHealth struct {
	Forwarder     shaping.ForwarderStats
	SamplingError string
}

func (r *Runtime) BandwidthMonitorHealth(ctx context.Context) BandwidthHealth {
	stats, err := r.bandwidth.ForwarderStats(ctx)
	_, sampleErr := r.traffic.Snapshot()
	if sampleErr != nil {
		err = sampleErr
	}
	return BandwidthHealth{Forwarder: stats, SamplingError: errorText(err)}
}

func (r *Runtime) BandwidthHistory(mac string, since time.Time, granularity string) []trafficmetrics.Bucket {
	return r.traffic.History(mac, since, granularity)
}

func (r *Runtime) StartAllBandwidthMonitors(ctx context.Context) error {
	original := make(map[string]struct{})
	for _, target := range r.bandwidth.MonitoringSnapshot() {
		original[target.MAC.String()] = struct{}{}
	}
	var started []net.HardwareAddr
	for _, current := range r.Devices() {
		if !current.Online || current.Role != device.RolePeer || !current.IP.Is4() {
			continue
		}
		mac, err := net.ParseMAC(current.MAC)
		if err != nil {
			continue
		}
		if err := r.StartBandwidthMonitor(ctx, ControlTarget{IP: current.IP, MAC: mac}); err != nil {
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			var rollbackErr error
			for index := len(started) - 1; index >= 0; index-- {
				rollbackErr = errors.Join(rollbackErr, r.StopBandwidthMonitor(rollbackCtx, started[index]))
			}
			cancel()
			return errors.Join(fmt.Errorf("monitor all rollback after %s: %w", current.MAC, err), rollbackErr)
		}
		if _, existed := original[mac.String()]; !existed {
			started = append(started, mac)
		}
	}
	return nil
}

func (r *Runtime) StopAllBandwidthMonitors(ctx context.Context) error {
	var result error
	for _, target := range r.bandwidth.MonitoringSnapshot() {
		if err := r.StopBandwidthMonitor(ctx, target.MAC); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (r *Runtime) ControlCommands(auditor ControlAuditor, factory ControlControllerFactory) *ControlCommands {
	networkContext := r.Network()
	if factory == nil {
		factory = runtimeControlControllerFactory{driver: r.driver}
	}
	return NewControlCommands(nil, ControlDependencies{
		Devices: r.registry,
		Scope: ControlScope{
			Prefix:  networkContext.Prefix,
			LocalIP: networkContext.Local.IP, LocalMAC: networkContext.Local.MAC,
			GatewayIP: networkContext.Gateway.IP, GatewayMAC: networkContext.Gateway.MAC,
		},
		Auditor: auditor, ControllerFactory: factory, Lifecycle: r.control, Publish: r.publish,
		DisruptiveGuard: func(target ControlTarget) error {
			if r.bandwidth.Contains(target.MAC) {
				return errors.New("remove the bandwidth limit before disconnecting this device")
			}
			return nil
		},
	})
}

type runtimeControlControllerFactory struct{ driver capture.Driver }

func (f runtimeControlControllerFactory) Prepare(_ context.Context, _ ControlRequest, scope ControlScope) (ControlControllerLease, error) {
	controller, err := control.NewController(f.driver,
		control.Endpoint{IP: scope.LocalIP, MAC: scope.LocalMAC},
		control.Endpoint{IP: scope.GatewayIP, MAC: scope.GatewayMAC},
		scope.Prefix, control.Options{},
	)
	if err != nil {
		return ControlControllerLease{}, err
	}
	return ControlControllerLease{Controller: controller}, nil
}

func (r *Runtime) SetNickname(mac net.HardwareAddr, nickname string) error {
	if r.metadata == nil || r.settings == nil {
		return errors.New("runtime metadata editing is not configured")
	}
	if _, err := r.settings.SetNickname(mac, nickname); err != nil {
		return err
	}
	r.metadata.SetNickname(mac, nickname)
	r.service.RefreshMetadata(mac.String())
	return nil
}

func (r *Runtime) RemoveNickname(mac net.HardwareAddr) error {
	if r.metadata == nil || r.settings == nil {
		return errors.New("runtime metadata editing is not configured")
	}
	if _, err := r.settings.RemoveNickname(mac); err != nil {
		return err
	}
	r.metadata.RemoveNickname(mac)
	r.service.RefreshMetadata(mac.String())
	return nil
}

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
	defer r.doneOnce.Do(func() { close(r.done) })
	r.publish(Event{Kind: EventRuntimeStarting})

	workerResults := make(chan error, 4)
	var eventWorkers sync.WaitGroup
	eventWorkers.Add(1)
	go func() {
		defer eventWorkers.Done()
		r.forwardEvents(workerCtx)
	}()
	var persistenceWorker sync.WaitGroup
	if r.history != nil {
		persistenceWorker.Add(1)
		go func() {
			defer persistenceWorker.Done()
			r.persistHistory(workerCtx)
		}()
	}
	go func() { workerResults <- workerError(StageCapture, r.service.Run(workerCtx)) }()
	go func() {
		workerResults <- workerError(StageDiscovery, r.scanner.Run(workerCtx, r.network.Prefix, r.config.ScanInterval))
	}()
	go func() { workerResults <- r.watchNetwork(workerCtx) }()
	go func() { workerResults <- r.traffic.Run(workerCtx) }()
	r.publish(Event{Kind: EventRuntimeStarted})

	first := <-workerResults
	r.publish(Event{Kind: EventRuntimeStopping, Err: first})
	r.traffic.StopAllSessions(time.Now().UTC())
	cancel()
	second := <-workerResults
	third := <-workerResults
	fourth := <-workerResults
	first = meaningfulError(first, second, third, fourth, ctx.Err())
	controlCtx, cancelControl := context.WithTimeout(context.Background(), 5*time.Second)
	controlErr := r.control.RestoreAll(controlCtx, "runtime shutdown or network change")
	cancelControl()
	bandwidthCtx, cancelBandwidth := context.WithTimeout(context.Background(), 5*time.Second)
	bandwidthErr := r.bandwidth.Clear(bandwidthCtx)
	monitorErr := r.bandwidth.ClearMonitoring(bandwidthCtx)
	cancelBandwidth()
	closeErr := r.service.Close()
	cancel()
	eventWorkers.Wait()
	persistenceWorker.Wait()

	r.mu.Lock()
	r.running = false
	r.stopped = true
	r.cancel = nil
	r.mu.Unlock()
	result := errors.Join(first, stageError(StageShutdown, controlErr), stageError(StageShutdown, bandwidthErr), stageError(StageShutdown, monitorErr), stageError(StageShutdown, closeErr))
	r.publish(Event{Kind: EventRuntimeStopped, Err: result})
	return result
}

func (r *Runtime) forwardEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-r.service.Events():
			if event.Kind == core.EventAddressChanged {
				reconcileCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := r.bandwidth.ReconcileDevice(reconcileCtx, event.Device)
				cancel()
				if err != nil {
					r.publish(Event{Kind: EventBandwidthMonitoringFailed, Device: &event.Device, Err: err})
				}
			}
			r.publish(eventFromCore(event))
			r.schedulePersist()
		case event := <-r.monitor.Events():
			r.publish(eventFromDefense(event))
			r.schedulePersist()
		case event := <-r.ipv6.Events():
			if event.Kind == discovery.IPv6RouterIdentityConflict || event.Kind == discovery.IPv6RouterIdentityRestored {
				kind := defense.GatewayIdentityConflict
				if event.Kind == discovery.IPv6RouterIdentityRestored {
					kind = defense.GatewayIdentityRestored
				}
				r.publish(eventFromDefense(defense.Event{Kind: kind, ObservedAt: event.ObservedAt,
					GatewayIP: event.RouterIP, ExpectedMAC: event.ExpectedMAC, ClaimedMAC: event.ClaimedMAC,
					Baseline: defense.BaselineLearned}))
			}
			r.schedulePersist()
		case <-r.traffic.Changes():
			r.schedulePersist()
		}
	}
}

func (r *Runtime) publish(event Event) {
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	select {
	case r.events <- event:
	default:
		r.dropped.Add(1)
	}
}

func (r *Runtime) handleScanEvent(event discovery.ScanEvent) { r.publish(eventFromScan(event)) }

func (r *Runtime) schedulePersist() {
	if r.history == nil {
		return
	}
	select {
	case r.persist <- struct{}{}:
	default:
	}
}

func (r *Runtime) persistHistory(ctx context.Context) {
	const debounce = 250 * time.Millisecond
	var timer *time.Timer
	var timerC <-chan time.Time
	flush := func() {
		snapshot := history.Snapshot{Devices: r.Devices(), Conflicts: r.ConflictHistory(), IPv6Routers: r.ipv6.State(), Traffic: r.traffic.State()}
		snapshot = history.Prune(snapshot, time.Now().UTC().Add(-r.config.HistoryRetention))
		err := r.history.Save(snapshot)
		r.mu.Lock()
		r.persistErr = err
		r.mu.Unlock()
		if err != nil {
			r.publish(Event{Kind: EventPersistenceFailed, Err: stageError(StagePersistence, err)})
		}
	}
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			flush()
			return
		case <-r.persist:
			if timer == nil {
				timer = time.NewTimer(debounce)
			} else if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(debounce)
			timerC = timer.C
		case <-timerC:
			flush()
			timerC = nil
		}
	}
}

func (r *Runtime) watchNetwork(ctx context.Context) error {
	ticker := time.NewTicker(r.config.NetworkCheck)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			route, err := r.gateway.Discover(ctx)
			if err != nil {
				return stageError(StageNetworkChange, fmt.Errorf("check default route: %w", err))
			}
			if route != r.route {
				return stageError(StageNetworkChange, fmt.Errorf("%w: was %s via %s, now %s via %s",
					ErrNetworkChanged, r.route.GatewayIP, r.route.InterfaceIP, route.GatewayIP, route.InterfaceIP))
			}
		}
	}
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
	r.doneOnce.Do(func() { close(r.done) })
	controlCtx, cancelControl := context.WithTimeout(context.Background(), 5*time.Second)
	controlErr := r.control.RestoreAll(controlCtx, "runtime closed")
	cancelControl()
	bandwidthCtx, cancelBandwidth := context.WithTimeout(context.Background(), 5*time.Second)
	bandwidthErr := r.bandwidth.Clear(bandwidthCtx)
	monitorErr := r.bandwidth.ClearMonitoring(bandwidthCtx)
	cancelBandwidth()
	return errors.Join(controlErr, bandwidthErr, monitorErr, r.driver.Close())
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
	if config.NetworkCheck <= 0 {
		config.NetworkCheck = 5 * time.Second
	}
	if config.DeviceRetention <= 0 {
		config.DeviceRetention = 24 * time.Hour
	}
	if config.HistoryRetention <= 0 {
		config.HistoryRetention = 90 * 24 * time.Hour
	}
	if config.IPv6AddressRetention <= 0 {
		config.IPv6AddressRetention = 24 * time.Hour
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

func workerError(stage Stage, err error) error {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return stageError(stage, err)
}
