package main

import (
	"context"
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
	selected, prefix, err := selectedInterface(selection, *prefixText)
	if err != nil {
		return err
	}
	resolver, err := metadata.NewResolver(config.Nicknames)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	selected.Prefixes = []netip.Prefix{prefix}
	dependencies := app.DefaultDependencies()
	dependencies.Metadata = resolver
	dependencies.Settings = store
	dependencies.History = history.NewStore(store.Path() + ".history.json")
	runtime, err := app.Bootstrap(ctx, dependencies, app.Config{
		Interface: selected, ScanInterval: *interval, ProbeDelay: 2 * time.Millisecond,
		MaximumHosts: *maxHosts, PinnedGatewayMAC: parseStoredMAC(config.GatewayMAC),
	})
	if err != nil {
		return err
	}
	defer runtime.Close()
	result := make(chan error, 1)
	go func() { result <- runtime.Run(ctx) }()
	fmt.Printf("monitoring %s on %s; press Ctrl-C to stop\n", runtime.Network().Prefix.Masked(), selected.Name)
	for {
		select {
		case event := <-runtime.Events():
			printRuntimeEvent(event)
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

func printRuntimeEvent(event app.Event) {
	if event.Device != nil {
		fmt.Printf("device %-15s  %-17s  %-24s  online=%t\n",
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
