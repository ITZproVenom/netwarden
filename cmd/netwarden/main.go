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
	"strings"
	"syscall"
	"time"

	"github.com/amdzy/NetWarden/internal/app"
	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/capture/helper"
	"github.com/amdzy/NetWarden/internal/capture/helperclient"
	"github.com/amdzy/NetWarden/internal/capture/pcapdriver"
	appconfig "github.com/amdzy/NetWarden/internal/config"
	"github.com/amdzy/NetWarden/internal/discovery"
	"github.com/amdzy/NetWarden/internal/history"
	"github.com/amdzy/NetWarden/internal/metadata"
	networkgateway "github.com/amdzy/NetWarden/internal/network/gateway"
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
		return listInterfaces()
	case "route":
		return showRoute()
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
	case "capture-helper":
		return serveCaptureHelper(args[1:])
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
  netwarden scan [--interface NAME] [--prefix CIDR] [--duration 5s]
  netwarden monitor [--interface NAME] [--prefix CIDR]
  netwarden devices [--since 24h] [--json]
  netwarden conflicts [--since 168h] [--json]
  netwarden history prune --older-than 2160h
  netwarden history clear
  netwarden resolve --gateway IP [--interface NAME] [--timeout 3s]
  netwarden config show
  netwarden config set-interface NAME
  netwarden config set-gateway-mac MAC
  netwarden config remove-gateway-mac
  netwarden nickname set MAC NAME
  netwarden nickname remove MAC

Packet capture and transmission normally require administrator/root privileges.
Use NetWarden only on networks you are authorized to administer.
`)
}

func listInterfaces() error {
	interfaces, err := pcapdriver.ListInterfaces()
	if err != nil {
		return err
	}
	if len(interfaces) == 0 {
		return errors.New("no IPv4 capture interfaces found")
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

func showRoute() error {
	route, err := (networkgateway.SystemDiscoverer{}).Discover(context.Background())
	if err != nil {
		return err
	}
	fmt.Println("interface IPv4:", route.InterfaceIP)
	fmt.Println("default gateway:", route.GatewayIP)
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
		if len(args) != 1 {
			return errors.New("usage: netwarden config show")
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
