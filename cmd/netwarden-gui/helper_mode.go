package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

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
	connectAddress := flags.String("connect", "", "authenticated parent connection")
	connectToken := flags.String("token", "", "one-time parent authentication token")
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
	filter := fmt.Sprintf("arp or icmp6 or ((ip or ip6) and ether dst %s)", selected.MAC.String())
	driver, err := pcapdriver.Open(selected.Name, pcapdriver.Config{Promiscuous: true, Filter: filter})
	if err != nil {
		return true, err
	}
	input, output, closeTransport, err := helperTransport(*connectAddress, *connectToken)
	if err != nil {
		_ = driver.Close()
		return true, err
	}
	defer closeTransport()
	return true, helper.Serve(context.Background(), driver, selected.MAC, prefix.Addr(), route.GatewayIP, prefix, selected.Prefixes, input, output)
}

func helperTransport(address, token string) (io.Reader, io.Writer, func() error, error) {
	if address == "" && token == "" {
		return os.Stdin, os.Stdout, func() error { return nil }, nil
	}
	if address == "" || token == "" {
		return nil, nil, nil, errors.New("helper connection and token must be provided together")
	}
	connection, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connect to NetWarden: %w", err)
	}
	if _, err := fmt.Fprintln(connection, token); err != nil {
		_ = connection.Close()
		return nil, nil, nil, fmt.Errorf("authenticate to NetWarden: %w", err)
	}
	reader := bufio.NewReader(connection)
	acknowledgement, err := reader.ReadString('\n')
	if err != nil || acknowledgement != "ok\n" {
		_ = connection.Close()
		return nil, nil, nil, errors.New("NetWarden rejected the helper connection")
	}
	return reader, connection, connection.Close, nil
}
