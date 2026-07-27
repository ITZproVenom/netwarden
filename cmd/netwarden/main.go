package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/amdzy/NetWarden/internal/app"
	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/capture/helper"
	"github.com/amdzy/NetWarden/internal/capture/helperclient"
	"github.com/amdzy/NetWarden/internal/capture/pcapdriver"
	appconfig "github.com/amdzy/NetWarden/internal/config"
	"github.com/amdzy/NetWarden/internal/control"
	"github.com/amdzy/NetWarden/internal/controlaudit"
	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/discovery"
	"github.com/amdzy/NetWarden/internal/history"
	"github.com/amdzy/NetWarden/internal/localapi"
	"github.com/amdzy/NetWarden/internal/metadata"
	networkgateway "github.com/amdzy/NetWarden/internal/network/gateway"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "netwarden:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}
	switch args[0] {
	case "interfaces":
		return listInterfaces(args[1:])
	case "route":
		return showRoute(args[1:])
	case "version":
		return showVersion(args[1:])
	case "scan":
		return scan(args[1:])
	case "monitor":
		return monitor(args[1:])
	case "resolve":
		return resolve(args[1:])
	case "config":
		return configure(args[1:])
	case "nickname":
		return nickname(args[1:])
	case "devices":
		return showHistory(args[1:], false)
	case "conflicts":
		return showHistory(args[1:], true)
	case "history":
		return manageHistory(args[1:])
	case "audit":
		return manageAudit(args[1:])
	case "status":
		return runtimeStatus(args[1:])
	case "refresh":
		return runtimeAction("/refresh")
	case "pause":
		return runtimeAction("/scan/pause")
	case "resume":
		return runtimeAction("/scan/resume")
	case "capture-helper":
		return serveCaptureHelper(args[1:])
	case "disconnect", "disconnect-all", "poison":
		return activeControlCommand(args[0], args[1:])
	case "restore", "restore-all", "stop-poison":
		return recoveryControlCommand(args[0], args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func printUsage() {
	fmt.Print(`NetWarden network diagnostics

Usage:
  netwarden interfaces
  netwarden route
  netwarden version [--json]
  netwarden scan [--interface NAME] [--prefix CIDR] [--duration 5s]
  netwarden monitor [--interface NAME] [--prefix CIDR]
  netwarden devices [--since 24h] [--json]
  netwarden conflicts [--since 168h] [--json]
  netwarden history prune --older-than 2160h
  netwarden history clear
  netwarden audit [--since 24h] [--operation NAME] [--json]
  netwarden audit prune [--older-than 2160h]
  netwarden audit clear
  netwarden status [--json]
  netwarden refresh
  netwarden pause
  netwarden resume
  netwarden resolve --gateway IP [--interface NAME] [--timeout 3s]
  netwarden config show
  netwarden config set-interface NAME
  netwarden config set-gateway-mac MAC
  netwarden config remove-gateway-mac
  netwarden nickname set MAC NAME
  netwarden nickname remove MAC
  netwarden disconnect IP MAC                         
  netwarden disconnect-all                            
  netwarden poison IP MAC                             
  netwarden restore IP MAC
  netwarden restore-all
  netwarden stop-poison IP MAC

Packet capture and transmission normally require administrator/root privileges.
Use NetWarden only on networks you are authorized to administer.
`)
}

func activeControlCommand(name string, args []string) error {
	commands, err := cliControlCommands()
	if err != nil {
		return err
	}
	switch name {
	case "disconnect", "poison":
		if len(args) != 2 {
			return fmt.Errorf("usage: netwarden %s IP MAC", name)
		}
		target, err := parseControlTarget(args[0], args[1])
		if err != nil {
			return err
		}
		if name == "disconnect" {
			return commands.Disconnect(context.Background(), target)
		}
		return commands.StartContinuous(context.Background(), target)
	case "disconnect-all":
		if len(args) != 0 {
			return errors.New("usage: netwarden disconnect-all")
		}
		return commands.DisconnectAll(context.Background())
	default:
		return fmt.Errorf("unknown active-control command %q", name)
	}
}

func manageAudit(args []string) error {
	settings, _, err := loadConfig()
	if err != nil {
		return err
	}
	store := controlaudit.NewStore(settings.Path() + ".control-audit.jsonl")
	if len(args) > 0 && args[0] == "clear" {
		if len(args) != 1 {
			return errors.New("usage: netwarden audit clear")
		}
		return store.Clear()
	}
	if len(args) > 0 && args[0] == "prune" {
		flags := flag.NewFlagSet("audit prune", flag.ContinueOnError)
		olderThan := flags.Duration("older-than", 90*24*time.Hour, "remove audit events older than this duration")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *olderThan <= 0 {
			return errors.New("older-than must be positive")
		}
		return store.Prune(time.Now().UTC().Add(-*olderThan))
	}
	flags := flag.NewFlagSet("audit", flag.ContinueOnError)
	since := flags.Duration("since", 0, "only events within this duration")
	operation := flags.String("operation", "", "filter by operation")
	outcome := flags.String("outcome", "", "filter by outcome")
	jsonOutput := flags.Bool("json", false, "write JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	query := controlaudit.Query{Operation: app.ControlOperation(*operation), Outcome: *outcome}
	if *since < 0 {
		return errors.New("since cannot be negative")
	}
	if *since > 0 {
		query.Since = time.Now().UTC().Add(-*since)
	}
	events, err := store.Query(query)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(events)
	}
	for _, event := range events {
		fmt.Printf("%s %-20s %-28s targets=%d\n", event.At.Format(time.RFC3339), event.Operation, event.Outcome, len(event.Targets))
	}
	return nil
}

func runtimeStatePath() (string, error) {
	settings, _, err := loadConfig()
	if err != nil {
		return "", err
	}
	return settings.Path() + ".runtime.json", nil
}

func runtimeStatus(args []string) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	jsonOutput := flags.Bool("json", false, "write JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	path, err := runtimeStatePath()
	if err != nil {
		return err
	}
	var status app.Status
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := localapi.Call(ctx, path, "GET", "/status", &status); err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(status)
	}
	fmt.Printf("running=%t scanning=%t periodic=%t devices=%d dropped=%d\n", status.Running, status.Scanning, status.PeriodicScanEnabled, status.DeviceCount, status.DroppedEvents)
	if status.LastPersistenceError != "" {
		fmt.Println("persistence error:", status.LastPersistenceError)
	}
	return nil
}

func runtimeAction(endpoint string) error {
	path, err := runtimeStatePath()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return localapi.Call(ctx, path, "POST", endpoint, nil)
}

func recoveryControlCommand(name string, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	commands, closeDriver, err := cliRecoveryCommands(ctx)
	if err != nil {
		return err
	}
	defer closeDriver()
	switch name {
	case "restore", "stop-poison":
		if len(args) != 2 {
			return fmt.Errorf("usage: netwarden %s IP MAC", name)
		}
		target, err := parseControlTarget(args[0], args[1])
		if err != nil {
			return err
		}
		if name == "restore" {
			err = commands.Restore(ctx, target)
		} else {
			err = commands.StopContinuous(ctx, target)
		}
		if err == nil {
			fmt.Println("restored verified gateway mapping for", target.IP)
		}
		return err
	case "restore-all":
		if len(args) != 0 {
			return errors.New("usage: netwarden restore-all")
		}
		err := commands.RestoreAll(ctx)
		if err == nil {
			fmt.Println("restored verified gateway mapping for eligible peers")
		}
		return err
	default:
		return fmt.Errorf("unknown recovery command %q", name)
	}
}

func cliRecoveryCommands(ctx context.Context) (*app.ControlCommands, func() error, error) {
	settings, config, err := loadConfig()
	if err != nil {
		return nil, nil, err
	}
	snapshot, err := history.NewStore(settings.Path() + ".history.json").Load()
	if err != nil {
		return nil, nil, err
	}
	selected, _, err := selectedInterface(config.Interface, "")
	if err != nil {
		return nil, nil, err
	}
	route, err := (networkgateway.SystemDiscoverer{}).Discover(ctx)
	if err != nil {
		return nil, nil, err
	}
	prefix, err := interfaceRoutePrefix(selected, route)
	if err != nil {
		return nil, nil, err
	}
	driver, err := pcapdriver.Open(selected.Name, pcapdriver.Config{Promiscuous: true, Filter: "arp"})
	if err != nil {
		return nil, nil, err
	}
	closeDriver := driver.Close
	gatewayMAC, err := discovery.ResolveARP(ctx, driver, selected.MAC, route.InterfaceIP, route.GatewayIP)
	if err != nil {
		_ = closeDriver()
		return nil, nil, fmt.Errorf("resolve verified gateway for recovery: %w", err)
	}
	if pinned := parseStoredMAC(config.GatewayMAC); len(pinned) == 6 && !strings.EqualFold(pinned.String(), gatewayMAC.String()) {
		_ = closeDriver()
		return nil, nil, errors.New("live gateway identity differs from the pinned baseline; recovery was not sent")
	}
	controller, err := control.NewController(driver,
		control.Endpoint{IP: route.InterfaceIP, MAC: selected.MAC},
		control.Endpoint{IP: route.GatewayIP, MAC: gatewayMAC}, prefix,
		control.Options{},
	)
	if err != nil {
		_ = closeDriver()
		return nil, nil, err
	}
	commands := app.NewControlCommands(controller, app.ControlDependencies{
		Devices: snapshotDeviceSource{devices: snapshot.Devices},
		Scope: app.ControlScope{
			Prefix: prefix, LocalIP: route.InterfaceIP, LocalMAC: selected.MAC,
			GatewayIP: route.GatewayIP, GatewayMAC: gatewayMAC,
		},
		Auditor: controlaudit.NewStore(settings.Path() + ".control-audit.jsonl"),
	})
	return commands, closeDriver, nil
}

func interfaceRoutePrefix(selected pcapdriver.Interface, route networkgateway.Route) (netip.Prefix, error) {
	for _, candidate := range selected.Prefixes {
		if candidate.Addr() == route.InterfaceIP && candidate.Masked().Contains(route.GatewayIP) {
			return netip.PrefixFrom(route.InterfaceIP, candidate.Bits()), nil
		}
	}
	return netip.Prefix{}, errors.New("selected interface does not match the current default route")
}

type snapshotDeviceSource struct{ devices []device.Device }

func (s snapshotDeviceSource) Snapshot() []device.Device {
	return append([]device.Device(nil), s.devices...)
}

type cliActiveControllerFactory struct {
	selected pcapdriver.Interface
	route    networkgateway.Route
	prefix   netip.Prefix
	pinned   net.HardwareAddr
}

func (f cliActiveControllerFactory) Prepare(ctx context.Context, _ app.ControlRequest, _ app.ControlScope) (app.ControlControllerLease, error) {
	driver, err := pcapdriver.Open(f.selected.Name, pcapdriver.Config{Promiscuous: true, Filter: "arp"})
	if err != nil {
		return app.ControlControllerLease{}, err
	}
	closeDriver := driver.Close
	gatewayMAC, err := discovery.ResolveARP(ctx, driver, f.selected.MAC, f.route.InterfaceIP, f.route.GatewayIP)
	if err != nil {
		_ = closeDriver()
		return app.ControlControllerLease{}, fmt.Errorf("resolve verified gateway for control preparation: %w", err)
	}
	if len(f.pinned) == 6 && !strings.EqualFold(f.pinned.String(), gatewayMAC.String()) {
		_ = closeDriver()
		return app.ControlControllerLease{}, errors.New("live gateway identity differs from the pinned baseline")
	}
	controller, err := control.NewController(driver,
		control.Endpoint{IP: f.route.InterfaceIP, MAC: f.selected.MAC},
		control.Endpoint{IP: f.route.GatewayIP, MAC: gatewayMAC}, f.prefix,
		control.Options{},
	)
	if err != nil {
		_ = closeDriver()
		return app.ControlControllerLease{}, err
	}
	return app.ControlControllerLease{Controller: controller, Close: closeDriver}, nil
}

func cliControlCommands() (*app.ControlCommands, error) {
	settings, config, err := loadConfig()
	if err != nil {
		return nil, err
	}
	snapshot, err := history.NewStore(settings.Path() + ".history.json").Load()
	if err != nil {
		return nil, err
	}
	selected, _, err := selectedInterface(config.Interface, "")
	if err != nil {
		return nil, err
	}
	route, err := (networkgateway.SystemDiscoverer{}).Discover(context.Background())
	if err != nil {
		return nil, err
	}
	var prefix netip.Prefix
	for _, candidate := range selected.Prefixes {
		if candidate.Addr() == route.InterfaceIP && candidate.Masked().Contains(route.GatewayIP) {
			prefix = netip.PrefixFrom(route.InterfaceIP, candidate.Bits())
			break
		}
	}
	if !prefix.IsValid() {
		return nil, errors.New("selected interface does not match the current default route")
	}
	return app.NewControlCommands(nil, app.ControlDependencies{
		Devices: snapshotDeviceSource{devices: snapshot.Devices},
		Scope: app.ControlScope{
			Prefix: prefix, LocalIP: route.InterfaceIP, LocalMAC: selected.MAC,
			GatewayIP: route.GatewayIP, GatewayMAC: parseStoredMAC(config.GatewayMAC),
		},
		Auditor: controlaudit.NewStore(settings.Path() + ".control-audit.jsonl"),
		ControllerFactory: cliActiveControllerFactory{
			selected: selected, route: route, prefix: prefix, pinned: parseStoredMAC(config.GatewayMAC),
		},
	}), nil
}

func parseControlTarget(ipText, macText string) (app.ControlTarget, error) {
	ip, err := netip.ParseAddr(ipText)
	if err != nil || !ip.Is4() {
		return app.ControlTarget{}, fmt.Errorf("invalid target IPv4 address %q", ipText)
	}
	mac, err := net.ParseMAC(macText)
	if err != nil || len(mac) != 6 {
		return app.ControlTarget{}, fmt.Errorf("invalid target Ethernet MAC %q", macText)
	}
	return app.ControlTarget{IP: ip, MAC: mac}, nil
}

func listInterfaces(args []string) error {
	flags := flag.NewFlagSet("interfaces", flag.ContinueOnError)
	jsonOutput := flags.Bool("json", false, "write JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	interfaces, err := pcapdriver.ListInterfaces()
	if err != nil {
		return err
	}
	if len(interfaces) == 0 {
		return errors.New("no IPv4 capture interfaces found")
	}
	if *jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(interfaces)
	}
	for _, candidate := range interfaces {
		label := candidate.Name
		if candidate.SystemName != "" && candidate.SystemName != candidate.Name {
			label += " (" + candidate.SystemName + ")"
		}
		fmt.Println(label)
		if candidate.Description != "" {
			fmt.Println("  description:", candidate.Description)
		}
		fmt.Println("  MAC:", candidate.MAC)
		for _, prefix := range candidate.Prefixes {
			fmt.Println("  IPv4:", prefix)
		}
	}
	return nil
}

func showRoute(args []string) error {
	flags := flag.NewFlagSet("route", flag.ContinueOnError)
	jsonOutput := flags.Bool("json", false, "write JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	route, err := (networkgateway.SystemDiscoverer{}).Discover(context.Background())
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(route)
	}
	fmt.Println("interface IPv4:", route.InterfaceIP)
	fmt.Println("default gateway:", route.GatewayIP)
	return nil
}

func showVersion(args []string) error {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	jsonOutput := flags.Bool("json", false, "write JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	info := map[string]string{"version": version, "commit": commit, "build_date": buildDate, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH}
	if build, ok := debug.ReadBuildInfo(); ok && version == "dev" && build.Main.Version != "" && build.Main.Version != "(devel)" {
		info["version"] = build.Main.Version
	}
	if *jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(info)
	}
	fmt.Printf("NetWarden %s (%s, %s) %s/%s %s\n", info["version"], info["commit"], info["build_date"], info["os"], info["arch"], info["go"])
	return nil
}

func scan(args []string) error {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	interfaceName := flags.String("interface", "", "pcap or system interface name")
	prefixText := flags.String("prefix", "", "IPv4 prefix to scan (defaults to interface prefix)")
	duration := flags.Duration("duration", 5*time.Second, "time to collect replies")
	maxHosts := flags.Int("max-hosts", 4094, "maximum addresses allowed in a scan")
	helperCommand := flags.String("helper-command", "", "privileged helper command, for example 'sudo ./netwarden'")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *duration <= 0 {
		return errors.New("duration must be positive")
	}

	store, config, err := loadConfig()
	if err != nil {
		return err
	}
	selection := *interfaceName
	if selection == "" {
		selection = config.Interface
	}
	selected, localPrefix, err := selectedInterface(selection, *prefixText)
	if err != nil {
		return err
	}
	enricher, err := metadata.NewResolver(config.Nicknames)
	if err != nil {
		return err
	}

	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, *duration)
	defer cancel()
	selected.Prefixes = []netip.Prefix{localPrefix}
	dependencies := app.DefaultDependencies()
	if *helperCommand != "" {
		dependencies.Open = helperOpen(ctx, *helperCommand)
	}
	dependencies.Metadata = enricher
	dependencies.Settings = store
	dependencies.History = history.NewStore(store.Path() + ".history.json")
	runtime, err := app.Bootstrap(ctx, dependencies, app.Config{
		Interface: selected, ScanInterval: time.Hour,
		ProbeDelay: 2 * time.Millisecond, MaximumHosts: *maxHosts,
		PinnedGatewayMAC: parseStoredMAC(config.GatewayMAC),
	})
	if err != nil {
		return err
	}
	defer runtime.Close()
	runtimeResult := make(chan error, 1)
	go func() { runtimeResult <- runtime.Run(ctx) }()

	for {
		select {
		case event := <-runtime.Events():
			if event.Device != nil {
				fmt.Printf("%-15s  %-17s  %-24s  %s\n", event.Device.IP, event.Device.MAC, event.Device.Name, event.Device.Vendor)
			}
			if event.Integrity != nil {
				fmt.Fprintf(os.Stderr, "network warning: gateway %s expected at %s but observed claim from %s\n",
					event.Integrity.GatewayIP, event.Integrity.ExpectedMAC, event.Integrity.ClaimedMAC)
			}
		case err := <-runtimeResult:
			if isContextEnd(err) {
				return nil
			}
			return err
		case <-ctx.Done():
			err := <-runtimeResult
			if !isContextEnd(err) {
				return err
			}
			return nil
		}
	}
}

func monitor(args []string) error {
	flags := flag.NewFlagSet("monitor", flag.ContinueOnError)
	interfaceName := flags.String("interface", "", "pcap or system interface name")
	prefixText := flags.String("prefix", "", "IPv4 prefix to scan (defaults to interface prefix)")
	maxHosts := flags.Int("max-hosts", 4094, "maximum addresses allowed in a scan")
	interval := flags.Duration("interval", 10*time.Second, "periodic discovery interval")
	jsonOutput := flags.Bool("json", false, "write newline-delimited JSON events")
	helperCommand := flags.String("helper-command", "", "privileged helper command, for example 'sudo ./netwarden'")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *interval <= 0 {
		return errors.New("interval must be positive")
	}
	store, config, err := loadConfig()
	if err != nil {
		return err
	}
	selection := *interfaceName
	if selection == "" {
		selection = config.Interface
	}
	resolver, err := metadata.NewResolver(config.Nicknames)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dependencies := app.DefaultDependencies()
	if *helperCommand != "" {
		dependencies.Open = helperOpen(ctx, *helperCommand)
	}
	dependencies.Metadata = resolver
	dependencies.Settings = store
	dependencies.History = history.NewStore(store.Path() + ".history.json")
	supervisor := app.NewSupervisor(func(factoryContext context.Context) (*app.Runtime, error) {
		selected, prefix, err := selectedInterface(selection, *prefixText)
		if err != nil {
			return nil, err
		}
		selected.Prefixes = []netip.Prefix{prefix}
		return app.Bootstrap(factoryContext, dependencies, app.Config{
			Interface: selected, ScanInterval: *interval, ProbeDelay: 2 * time.Millisecond,
			MaximumHosts: *maxHosts, PinnedGatewayMAC: parseStoredMAC(config.GatewayMAC),
		})
	}, time.Second)
	apiServer, err := localapi.Start(store.Path()+".runtime.json", localapi.Handlers{
		Status:   supervisor.Status,
		Refresh:  supervisor.ScanNow,
		Periodic: supervisor.SetPeriodicScanEnabled,
	})
	if err != nil {
		return fmt.Errorf("start local runtime API: %w", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = apiServer.Close(shutdownCtx)
	}()
	result := make(chan error, 1)
	go func() { result <- supervisor.Run(ctx) }()
	if !*jsonOutput {
		fmt.Println("monitoring network; press Ctrl-C to stop")
	}
	for {
		select {
		case event := <-supervisor.Events():
			printRuntimeEvent(event, *jsonOutput)
		case err := <-result:
			if isContextEnd(err) {
				return nil
			}
			return err
		case <-ctx.Done():
			err := <-result
			if isContextEnd(err) {
				return nil
			}
			return err
		}
	}
}

func helperOpen(ctx context.Context, commandText string) app.OpenDriver {
	return func(interfaceName string) (capture.Driver, error) {
		parts := strings.Fields(commandText)
		if len(parts) == 0 {
			return nil, errors.New("helper command is empty")
		}
		arguments := append([]string(nil), parts[1:]...)
		arguments = append(arguments, "capture-helper", "--interface", interfaceName)
		return helperclient.Open(ctx, parts[0], arguments...)
	}
}

func serveCaptureHelper(args []string) error {
	flags := flag.NewFlagSet("capture-helper", flag.ContinueOnError)
	interfaceName := flags.String("interface", "", "capture interface")
	if err := flags.Parse(args); err != nil {
		return err
	}
	selected, prefix, err := selectedInterface(*interfaceName, "")
	if err != nil {
		return err
	}
	driver, err := pcapdriver.Open(selected.Name, pcapdriver.Config{Promiscuous: true, Filter: "arp"})
	if err != nil {
		return err
	}
	return helper.Serve(context.Background(), driver, selected.MAC, prefix.Addr(), prefix, os.Stdin, os.Stdout)
}

func printRuntimeEvent(event app.Event, jsonOutput bool) {
	if jsonOutput {
		payload := map[string]any{"timestamp": time.Now().UTC(), "kind": eventKindName(event.Kind)}
		if event.Device != nil {
			payload["device"] = event.Device
		}
		if event.Integrity != nil {
			payload["integrity"] = event.Integrity
		}
		if event.Scan != nil {
			payload["scan"] = event.Scan
		}
		if event.Control != nil {
			payload["control"] = event.Control
		}
		if event.Err != nil {
			payload["error"] = event.Err.Error()
		}
		_ = json.NewEncoder(os.Stdout).Encode(payload)
		return
	}
	prefix := time.Now().Format("15:04:05") + " " + eventKindName(event.Kind) + ":"
	if event.Device != nil {
		fmt.Printf("%s %-15s  %-17s  %-24s  online=%t\n", prefix,
			event.Device.IP, event.Device.MAC, event.Device.Name, event.Device.Online)
	}
	if event.Integrity != nil {
		fmt.Fprintf(os.Stderr, "integrity gateway=%s expected=%s claimed=%s kind=%d count=%d\n",
			event.Integrity.GatewayIP, event.Integrity.ExpectedMAC, event.Integrity.ClaimedMAC,
			event.Integrity.Kind, event.Integrity.Count)
	}
	if event.Scan != nil && event.Scan.Err != nil {
		fmt.Fprintln(os.Stderr, "scan:", event.Scan.Err)
	}
	if event.Control != nil {
		fmt.Printf("%s operation=%s state=%s targets=%d reason=%s\n", prefix,
			event.Control.Operation, event.Control.State, len(event.Control.Targets), event.Control.Reason)
	}
	if event.Kind == app.EventPersistenceFailed && event.Err != nil {
		fmt.Fprintln(os.Stderr, "history:", event.Err)
	}
}

func eventKindName(kind app.EventKind) string {
	names := map[app.EventKind]string{
		app.EventDeviceObserved: "device_observed", app.EventDeviceReturnedOnline: "device_online",
		app.EventDeviceAddressChanged: "device_address_changed", app.EventDeviceIPConflict: "device_ip_conflict",
		app.EventDeviceOffline: "device_offline", app.EventDeviceRemoved: "device_removed",
		app.EventDeviceMetadataChanged: "device_metadata_changed", app.EventIntegrityWarning: "integrity_warning",
		app.EventScanStarted: "scan_started", app.EventScanCompleted: "scan_completed", app.EventScanFailed: "scan_failed",
		app.EventRuntimeStarting: "runtime_starting", app.EventRuntimeStarted: "runtime_started",
		app.EventRuntimeStopping: "runtime_stopping", app.EventRuntimeStopped: "runtime_stopped",
		app.EventPersistenceFailed: "persistence_failed", app.EventRuntimeRebuilding: "runtime_rebuilding",
		app.EventControlPrepared:                "control_prepared",
		app.EventControlTargetStateChanged:      "control_target_state_changed",
		app.EventControlRestorationStarted:      "control_restoration_started",
		app.EventControlRestorationCompleted:    "control_restoration_completed",
		app.EventControlBulkRollbackStarted:     "control_bulk_rollback_started",
		app.EventControlBulkRollbackCompleted:   "control_bulk_rollback_completed",
		app.EventControlContinuousWorkerStopped: "control_continuous_worker_stopped",
		app.EventControlAuditFailed:             "control_audit_failed",
	}
	if name := names[kind]; name != "" {
		return name
	}
	return fmt.Sprintf("event_%d", kind)
}

func resolve(args []string) error {
	flags := flag.NewFlagSet("resolve", flag.ContinueOnError)
	interfaceName := flags.String("interface", "", "pcap or system interface name")
	gatewayText := flags.String("gateway", "", "IPv4 address to resolve")
	timeout := flags.Duration("timeout", 3*time.Second, "resolution timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *gatewayText == "" {
		return errors.New("--gateway is required")
	}
	gateway, err := netip.ParseAddr(*gatewayText)
	if err != nil || !gateway.Is4() {
		return fmt.Errorf("invalid IPv4 gateway %q", *gatewayText)
	}
	if *timeout <= 0 {
		return errors.New("timeout must be positive")
	}

	_, config, err := loadConfig()
	if err != nil {
		return err
	}
	selection := *interfaceName
	if selection == "" {
		selection = config.Interface
	}
	selected, localPrefix, err := selectedInterface(selection, "")
	if err != nil {
		return err
	}
	if !localPrefix.Masked().Contains(gateway) {
		return fmt.Errorf("gateway %s is not within interface prefix %s", gateway, localPrefix.Masked())
	}
	driver, err := pcapdriver.Open(selected.Name, pcapdriver.Config{Promiscuous: true, Filter: "arp"})
	if err != nil {
		return err
	}
	defer driver.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	mac, err := discovery.ResolveARP(ctx, driver, selected.MAC, localPrefix.Addr(), gateway)
	if err != nil {
		return err
	}
	fmt.Printf("%s  %s\n", gateway, mac)
	return nil
}

func configure(args []string) error {
	if len(args) == 0 {
		return errors.New("config subcommand is required")
	}
	store, config, err := loadConfig()
	if err != nil {
		return err
	}
	switch args[0] {
	case "show":
		flags := flag.NewFlagSet("config show", flag.ContinueOnError)
		jsonOutput := flags.Bool("json", false, "write JSON")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(config)
		}
		fmt.Println("path:", store.Path())
		fmt.Println("interface:", config.Interface)
		fmt.Println("gateway MAC:", config.GatewayMAC)
		fmt.Println("nicknames:", len(config.Nicknames))
		return nil
	case "set-interface":
		if len(args) != 2 {
			return errors.New("usage: netwarden config set-interface NAME")
		}
		selected, _, err := selectedInterface(args[1], "")
		if err != nil {
			return err
		}
		if _, err := store.SetInterface(selected.Name); err != nil {
			return err
		}
		fmt.Println("saved interface:", selected.Name)
		return nil
	case "set-gateway-mac":
		if len(args) != 2 {
			return errors.New("usage: netwarden config set-gateway-mac MAC")
		}
		mac, err := net.ParseMAC(args[1])
		if err != nil || len(mac) != 6 {
			return fmt.Errorf("invalid Ethernet MAC address %q", args[1])
		}
		if _, err := store.SetGatewayMAC(mac); err != nil {
			return err
		}
		fmt.Println("saved gateway MAC:", strings.ToLower(mac.String()))
		return nil
	case "remove-gateway-mac":
		if len(args) != 1 {
			return errors.New("usage: netwarden config remove-gateway-mac")
		}
		if _, err := store.RemoveGatewayMAC(); err != nil {
			return err
		}
		fmt.Println("removed pinned gateway MAC")
		return nil
	default:
		return fmt.Errorf("unknown config command %q", args[0])
	}
}

func parseStoredMAC(value string) net.HardwareAddr {
	if value == "" {
		return nil
	}
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 {
		return nil
	}
	return mac
}

func showHistory(args []string, conflictsOnly bool) error {
	flags := flag.NewFlagSet("history-query", flag.ContinueOnError)
	since := flags.Duration("since", 0, "only records seen within this duration")
	mac := flags.String("mac", "", "filter by MAC address")
	onlineText := flags.String("online", "any", "device state: any, true, or false")
	jsonOutput := flags.Bool("json", false, "write JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *since < 0 {
		return errors.New("since cannot be negative")
	}
	query := history.Query{MAC: *mac}
	if *since > 0 {
		query.Since = time.Now().UTC().Add(-*since)
	}
	switch strings.ToLower(*onlineText) {
	case "any":
	case "true":
		value := true
		query.Online = &value
	case "false":
		value := false
		query.Online = &value
	default:
		return errors.New("online must be any, true, or false")
	}
	store, _, err := loadConfig()
	if err != nil {
		return err
	}
	snapshot, err := history.NewStore(store.Path() + ".history.json").Query(query)
	if err != nil {
		return err
	}
	if *jsonOutput {
		if conflictsOnly {
			return json.NewEncoder(os.Stdout).Encode(snapshot.Conflicts)
		}
		return json.NewEncoder(os.Stdout).Encode(snapshot.Devices)
	}
	if conflictsOnly {
		for _, conflict := range snapshot.Conflicts {
			fmt.Printf("%s gateway=%s claimed=%s count=%d active=%t\n", conflict.LastSeen.Format(time.RFC3339), conflict.GatewayIP, conflict.ClaimedMAC, conflict.Count, conflict.Active)
		}
		return nil
	}
	for _, current := range snapshot.Devices {
		fmt.Printf("%-15s %-17s %-24s last=%s online=%t\n", current.IP, current.MAC, current.Name, current.LastSeen.Format(time.RFC3339), current.Online)
	}
	return nil
}

func manageHistory(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: netwarden history prune --older-than DURATION | history clear")
	}
	settings, _, err := loadConfig()
	if err != nil {
		return err
	}
	store := history.NewStore(settings.Path() + ".history.json")
	switch args[0] {
	case "clear":
		if len(args) != 1 {
			return errors.New("usage: netwarden history clear")
		}
		return store.Clear()
	case "prune":
		flags := flag.NewFlagSet("history prune", flag.ContinueOnError)
		olderThan := flags.Duration("older-than", 90*24*time.Hour, "remove peer and conflict history older than this duration")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *olderThan <= 0 {
			return errors.New("older-than must be positive")
		}
		snapshot, err := store.Load()
		if err != nil {
			return err
		}
		return store.Save(history.Prune(snapshot, time.Now().UTC().Add(-*olderThan)))
	default:
		return fmt.Errorf("unknown history command %q", args[0])
	}
}

func nickname(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: netwarden nickname set MAC NAME | nickname remove MAC")
	}
	store, _, err := loadConfig()
	if err != nil {
		return err
	}
	mac, err := net.ParseMAC(args[1])
	if err != nil || len(mac) != 6 {
		return fmt.Errorf("invalid Ethernet MAC address %q", args[1])
	}
	switch args[0] {
	case "set":
		if len(args) < 3 {
			return errors.New("usage: netwarden nickname set MAC NAME")
		}
		name := strings.Join(args[2:], " ")
		if _, err := store.SetNickname(mac, name); err != nil {
			return err
		}
		fmt.Printf("saved nickname for %s: %s\n", strings.ToLower(mac.String()), strings.TrimSpace(name))
		return nil
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: netwarden nickname remove MAC")
		}
		if _, err := store.RemoveNickname(mac); err != nil {
			return err
		}
		fmt.Println("removed nickname for", strings.ToLower(mac.String()))
		return nil
	default:
		return fmt.Errorf("unknown nickname command %q", args[0])
	}
}

func loadConfig() (*appconfig.Store, appconfig.Config, error) {
	path := os.Getenv("NETWARDEN_CONFIG")
	if path == "" {
		var err error
		path, err = appconfig.DefaultPath()
		if err != nil {
			return nil, appconfig.Config{}, err
		}
	}
	store := appconfig.NewStore(path)
	config, err := store.Load()
	if err != nil {
		return nil, appconfig.Config{}, err
	}
	return store, config, nil
}

func selectedInterface(requested, requestedPrefix string) (pcapdriver.Interface, netip.Prefix, error) {
	interfaces, err := pcapdriver.ListInterfaces()
	if err != nil {
		return pcapdriver.Interface{}, netip.Prefix{}, err
	}
	selected, err := pcapdriver.SelectInterface(interfaces, requested)
	if err != nil {
		if errors.Is(err, pcapdriver.ErrSelectionRequired) {
			return pcapdriver.Interface{}, netip.Prefix{}, fmt.Errorf("%w; run 'netwarden interfaces' and pass --interface", err)
		}
		return pcapdriver.Interface{}, netip.Prefix{}, err
	}
	if len(selected.MAC) != 6 {
		return pcapdriver.Interface{}, netip.Prefix{}, fmt.Errorf("interface %q has no Ethernet MAC address", selected.Name)
	}

	if requestedPrefix != "" {
		prefix, err := netip.ParsePrefix(requestedPrefix)
		if err != nil || !prefix.Addr().Is4() {
			return pcapdriver.Interface{}, netip.Prefix{}, fmt.Errorf("invalid IPv4 prefix %q", requestedPrefix)
		}
		for _, local := range selected.Prefixes {
			if prefix.Masked().Contains(local.Addr()) {
				return selected, netip.PrefixFrom(local.Addr(), prefix.Bits()), nil
			}
		}
		return pcapdriver.Interface{}, netip.Prefix{}, fmt.Errorf("prefix %s does not contain an address assigned to %s", prefix, selected.Name)
	}
	for _, prefix := range selected.Prefixes {
		if prefix.Addr().Is4() && !prefix.Addr().IsLoopback() && !prefix.Addr().IsLinkLocalUnicast() {
			return selected, prefix, nil
		}
	}
	return pcapdriver.Interface{}, netip.Prefix{}, fmt.Errorf("interface %q has no usable IPv4 prefix", selected.Name)
}

func isContextEnd(err error) bool {
	return err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
