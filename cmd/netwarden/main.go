package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/amdzy/NetWarden/internal/capture/pcapdriver"
	"github.com/amdzy/NetWarden/internal/core"
	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/discovery"
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
	case "scan":
		return scan(args[1:])
	case "resolve":
		return resolve(args[1:])
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
  netwarden scan [--interface NAME] [--prefix CIDR] [--duration 5s]
  netwarden resolve --gateway IP [--interface NAME] [--timeout 3s]

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

	selected, localPrefix, err := selectedInterface(*interfaceName, *prefixText)
	if err != nil {
		return err
	}
	driver, err := pcapdriver.Open(selected.Name, pcapdriver.Config{Promiscuous: true, Filter: "arp"})
	if err != nil {
		return err
	}
	defer driver.Close()

	registry := device.NewRegistry()
	service := core.NewService(driver, registry, time.Minute, 10*time.Second)
	prober := discovery.NewARPProber(driver, selected.MAC, localPrefix.Addr())
	scanner := discovery.NewScanner(prober, *maxHosts, 2*time.Millisecond)

	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, *duration)
	defer cancel()
	serviceResult := make(chan error, 1)
	go func() { serviceResult <- service.Run(ctx) }()

	if err := scanner.Scan(ctx, localPrefix); err != nil {
		cancel()
		<-serviceResult
		return fmt.Errorf("scan %s: %w", localPrefix.Masked(), err)
	}
	for {
		select {
		case event := <-service.Events():
			fmt.Printf("%-15s  %s\n", event.Device.IP, event.Device.MAC)
		case err := <-serviceResult:
			if isContextEnd(err) {
				return nil
			}
			return err
		case <-ctx.Done():
			err := <-serviceResult
			if !isContextEnd(err) {
				return err
			}
			return nil
		}
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

	selected, localPrefix, err := selectedInterface(*interfaceName, "")
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
