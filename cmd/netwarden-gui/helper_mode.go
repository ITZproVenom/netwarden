package main

import (
	"context"
	"errors"
	"flag"
	"net/netip"
	"os"

	"github.com/amdzy/NetWarden/internal/capture/helper"
	"github.com/amdzy/NetWarden/internal/capture/pcapdriver"
	networkgateway "github.com/amdzy/NetWarden/internal/network/gateway"
)

const askpassEnvironment = "NETWARDEN_ASKPASS"

func runHelperMode() (bool, error) {
	if os.Getenv(askpassEnvironment) == "1" {
		return true, platformAskpass()
	}
	if len(os.Args) < 2 || os.Args[1] != "capture-helper" {
		return false, nil
	}
	flags := flag.NewFlagSet("capture-helper", flag.ContinueOnError)
	interfaceName := flags.String("interface", "", "capture interface")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return true, err
	}
	if *interfaceName == "" {
		return true, errors.New("capture interface is required")
	}
	selected, err := selectInterface(*interfaceName)
	if err != nil {
		return true, err
	}
	route, err := (networkgateway.SystemDiscoverer{}).Discover(context.Background())
	if err != nil {
		return true, err
	}
	var prefix netip.Prefix
	for _, candidate := range selected.Prefixes {
		if candidate.Addr() == route.InterfaceIP && candidate.Masked().Contains(route.GatewayIP) {
			prefix = candidate
			break
		}
	}
	if !prefix.IsValid() {
		return true, errors.New("selected interface does not contain the default IPv4 route")
	}
	driver, err := pcapdriver.Open(selected.Name, pcapdriver.Config{Promiscuous: true, Filter: "arp"})
	if err != nil {
		return true, err
	}
	return true, helper.Serve(context.Background(), driver, selected.MAC, prefix.Addr(), route.GatewayIP, prefix, os.Stdin, os.Stdout)
}
