// Package helper implements the narrow protocol used by a privileged capture subprocess.
package helper

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/packet"
	"github.com/amdzy/NetWarden/internal/shaping"
)

type Message struct {
	Type       string                       `json:"type"`
	RequestID  string                       `json:"request_id,omitempty"`
	Data       []byte                       `json:"data,omitempty"`
	CapturedAt time.Time                    `json:"captured_at,omitempty"`
	Error      string                       `json:"error,omitempty"`
	TargetIP   string                       `json:"target_ip,omitempty"`
	TargetIPs  []string                     `json:"target_ips,omitempty"`
	TargetMAC  string                       `json:"target_mac,omitempty"`
	Policy     *shaping.Policy              `json:"policy,omitempty"`
	Traffic    []shaping.DeviceTrafficStats `json:"traffic,omitempty"`
	Forwarder  *shaping.ForwarderStats      `json:"forwarder,omitempty"`
	Continuous bool                         `json:"continuous,omitempty"`
}

// Serve exposes filtered capture and only tightly scoped discovery, isolation,
// forwarding, and corrective ARP/NDP transmissions.
func Serve(ctx context.Context, driver capture.Driver, localMAC net.HardwareAddr, localIP, gatewayIP netip.Addr, prefix netip.Prefix, ipv6Prefixes []netip.Prefix, input io.Reader, output io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer driver.Close()
	encoder := json.NewEncoder(output)
	var outputMu sync.Mutex
	write := func(message Message) error {
		outputMu.Lock()
		defer outputMu.Unlock()
		return encoder.Encode(message)
	}
	var sendMu sync.Mutex
	sendFrame := frameSenderFunc(func(sendCtx context.Context, frame []byte) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return driver.Send(sendCtx, frame)
	})
	bandwidth, err := newBandwidthSession(ctx, localMAC, localIP, gatewayIP, prefix, sendFrame)
	if err != nil {
		return err
	}
	defer bandwidth.close()
	if err := write(Message{Type: "ready"}); err != nil {
		return err
	}
	runResult := make(chan error, 1)
	var gatewayMu sync.RWMutex
	var gatewayMAC net.HardwareAddr
	consume := func(frame capture.Frame) error {
		var ndpValid bool
		etherType := frameEtherType(frame.Data)
		switch etherType {
		case packet.EtherTypeARP:
			if message, err := packet.ParseARP(frame.Data); err == nil && message.SenderIP == gatewayIP && !bytes.Equal(message.SenderMAC, localMAC) {
				gatewayMu.Lock()
				if len(gatewayMAC) == 0 {
					gatewayMAC = append(net.HardwareAddr(nil), message.SenderMAC...)
				}
				gatewayMu.Unlock()
				bandwidth.observeGateway(message.SenderMAC)
			}
		case packet.EtherTypeIPv6:
			if message, err := packet.ParseNDP(frame.Data); err == nil {
				ndpValid = true
				bandwidth.observeNDP(message)
			}
		}
		if (etherType == etherTypeIPv4 || etherType == packet.EtherTypeIPv6) && !ndpValid &&
			(bandwidth.dropIsolated(frame.Data) || bandwidth.submit(frame.Data)) {
			return nil
		}
		if len(frame.Data) >= packet.EthernetHeaderLen && bytes.Equal(frame.Data[6:12], localMAC) {
			return nil
		}
		return write(Message{Type: "frame", Data: frame.Data, CapturedAt: frame.CapturedAt})
	}
	go func() {
		if borrowed, ok := driver.(capture.BorrowedFrameDriver); ok {
			runResult <- borrowed.RunBorrowed(ctx, consume)
		} else {
			runResult <- driver.Run(ctx, consume)
		}
	}()
	decoder := json.NewDecoder(input)
	for {
		var command Message
		if err := decoder.Decode(&command); err != nil {
			if errors.Is(err, io.EOF) {
				cancel()
				return normalizeRunError(<-runResult)
			}
			return err
		}
		switch command.Type {
		case "send":
			gatewayMu.RLock()
			verifiedGatewayMAC := append(net.HardwareAddr(nil), gatewayMAC...)
			gatewayMu.RUnlock()
			if err := ValidateOutboundFrame(command.Data, localMAC, verifiedGatewayMAC, localIP, gatewayIP, prefix, ipv6Prefixes); err != nil {
				_ = write(Message{Type: "error", Error: err.Error()})
				continue
			}
			if err := sendFrame(ctx, command.Data); err != nil {
				_ = write(Message{Type: "error", Error: err.Error()})
			}
		case "shape_set", "shape_remove", "monitor_set", "monitor_remove", "isolate_set", "isolate_remove":
			err := handleBandwidthCommand(ctx, bandwidth, command)
			result := Message{Type: "result", RequestID: command.RequestID}
			if err != nil {
				result.Error = err.Error()
			}
			if writeErr := write(result); writeErr != nil {
				return writeErr
			}
		case "shape_traffic":
			if command.RequestID == "" {
				_ = write(Message{Type: "error", Error: "bandwidth traffic request requires a request ID"})
				continue
			}
			stats := bandwidth.forwarder.Stats()
			if err := write(Message{Type: "result", RequestID: command.RequestID, Traffic: bandwidth.forwarder.DeviceTraffic(), Forwarder: &stats}); err != nil {
				return err
			}
		case "close":
			cancel()
			return normalizeRunError(<-runResult)
		default:
			_ = write(Message{Type: "error", Error: "unsupported helper command"})
		}
	}
}

func handleBandwidthCommand(ctx context.Context, bandwidth *bandwidthSession, command Message) error {
	if command.RequestID == "" {
		return errors.New("bandwidth command requires a request ID")
	}
	addressTexts := command.TargetIPs
	if len(addressTexts) == 0 {
		addressTexts = []string{command.TargetIP}
	}
	addresses := make([]netip.Addr, 0, len(addressTexts))
	for _, text := range addressTexts {
		ip, err := netip.ParseAddr(text)
		if err != nil {
			return fmt.Errorf("invalid bandwidth target IP: %w", err)
		}
		addresses = append(addresses, ip)
	}
	mac, err := net.ParseMAC(command.TargetMAC)
	if err != nil {
		return fmt.Errorf("invalid bandwidth target MAC: %w", err)
	}
	if command.Type == "shape_remove" {
		return bandwidth.removeRoutes(ctx, addresses, mac)
	}
	if command.Type == "monitor_set" {
		return bandwidth.monitorRoutes(ctx, addresses, mac)
	}
	if command.Type == "monitor_remove" {
		return bandwidth.removeMonitorRoutes(ctx, addresses, mac)
	}
	if command.Type == "isolate_set" {
		return bandwidth.isolateRoutes(ctx, addresses, mac, command.Continuous)
	}
	if command.Type == "isolate_remove" {
		return bandwidth.restoreIsolation(ctx, addresses, mac)
	}
	if command.Policy == nil {
		return errors.New("bandwidth policy is required")
	}
	return bandwidth.setRoutes(ctx, addresses, mac, *command.Policy)
}

func isIPFrame(frame []byte) bool {
	etherType := frameEtherType(frame)
	return etherType == 0x0800 || etherType == packet.EtherTypeIPv6
}

const etherTypeIPv4 = 0x0800

func frameEtherType(frame []byte) uint16 {
	if len(frame) < packet.EthernetHeaderLen {
		return 0
	}
	return binary.BigEndian.Uint16(frame[12:14])
}

func ValidateOutboundFrame(frame []byte, localMAC, gatewayMAC net.HardwareAddr, localIP, gatewayIP netip.Addr, prefix netip.Prefix, ipv6Prefixes []netip.Prefix) error {
	if err := ValidateDiscoveryFrame(frame, localMAC, localIP, prefix); err == nil {
		return nil
	}
	if err := ValidateIPv6DiscoveryFrame(frame, localMAC, ipv6Prefixes); err == nil {
		return nil
	}
	return ValidateControlFrame(frame, localMAC, gatewayMAC, localIP, gatewayIP, prefix)
}

func ValidateIPv6DiscoveryFrame(frame []byte, localMAC net.HardwareAddr, prefixes []netip.Prefix) error {
	message, err := packet.ParseNDP(frame)
	if err != nil || message.Type != packet.ICMPv6NeighborSolicitation {
		return errors.New("helper accepts only IPv6 Neighbor Solicitation discovery frames")
	}
	if !bytes.Equal(message.SourceMAC, localMAC) || len(frame) < packet.EthernetHeaderLen || !bytes.Equal(frame[6:12], localMAC) {
		return errors.New("IPv6 discovery sender MAC does not match the selected interface")
	}
	sourceAllowed, targetAllowed := false, false
	for _, prefix := range prefixes {
		if !prefix.IsValid() || !prefix.Addr().Is6() {
			continue
		}
		if message.SourceIP == prefix.Addr() {
			sourceAllowed = true
		}
		if prefix.Masked().Contains(message.TargetIP) {
			targetAllowed = true
		}
	}
	if !sourceAllowed || !targetAllowed || message.SourceIP == message.TargetIP {
		return errors.New("IPv6 discovery identities are outside the selected interface")
	}
	if message.DestinationIP != packet.SolicitedNodeMulticast(message.TargetIP) ||
		!bytes.Equal(message.DestinationMAC, packet.SolicitedNodeMulticastMAC(message.TargetIP)) {
		return errors.New("IPv6 discovery must use the target solicited-node multicast identity")
	}
	canonical, err := packet.MarshalNeighborSolicitation(packet.NeighborSolicitation{
		SourceIP: message.SourceIP, SourceMAC: localMAC, TargetIP: message.TargetIP,
	})
	if err != nil || !bytes.Equal(frame, canonical) {
		return errors.New("IPv6 discovery frame is not a canonical Neighbor Solicitation")
	}
	return nil
}

func ValidateControlFrame(frame []byte, localMAC, gatewayMAC net.HardwareAddr, localIP, gatewayIP netip.Addr, prefix netip.Prefix) error {
	message, err := packet.ParseARP(frame)
	if err != nil || len(frame) < packet.EthernetHeaderLen {
		return errors.New("helper accepts only Ethernet/IPv4 ARP frames")
	}
	if message.Operation != packet.ARPOpReply || message.SenderIP != gatewayIP {
		return errors.New("control frame must be an ARP reply for the active gateway")
	}
	if !prefix.Masked().Contains(message.TargetIP) || message.TargetIP == localIP || message.TargetIP == gatewayIP ||
		len(message.TargetMAC) != 6 || message.TargetMAC[0]&1 != 0 || bytes.Equal(message.TargetMAC, localMAC) || bytes.Equal(message.TargetMAC, gatewayMAC) {
		return errors.New("control target is outside the eligible local network")
	}
	if !bytes.Equal(frame[0:6], message.TargetMAC) || !bytes.Equal(frame[6:12], message.SenderMAC) {
		return errors.New("control Ethernet and ARP identities do not match")
	}
	isolation := bytes.Equal(message.SenderMAC, localMAC)
	restoration := len(gatewayMAC) == 6 && bytes.Equal(message.SenderMAC, gatewayMAC)
	if !isolation && !restoration {
		return errors.New("control sender is neither the local interface nor verified gateway")
	}
	return nil
}

func normalizeRunError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

func ValidateDiscoveryFrame(frame []byte, localMAC net.HardwareAddr, localIP netip.Addr, prefix netip.Prefix) error {
	message, err := packet.ParseARP(frame)
	if err != nil {
		return errors.New("helper accepts only Ethernet/IPv4 ARP frames")
	}
	if message.Operation != packet.ARPOpRequest {
		return errors.New("helper accepts only ARP discovery requests")
	}
	if !bytes.Equal(frame[0:6], []byte{255, 255, 255, 255, 255, 255}) || !bytes.Equal(message.TargetMAC, []byte{0, 0, 0, 0, 0, 0}) {
		return errors.New("ARP discovery must use broadcast Ethernet and an empty target MAC")
	}
	if len(frame) < packet.EthernetHeaderLen || !bytes.Equal(frame[6:12], localMAC) || !bytes.Equal(message.SenderMAC, localMAC) {
		return errors.New("ARP sender MAC does not match the selected interface")
	}
	if message.SenderIP != localIP {
		return errors.New("ARP sender IP does not match the selected interface")
	}
	if !prefix.Masked().Contains(message.TargetIP) || message.TargetIP == localIP {
		return errors.New("ARP target is outside the selected local network")
	}
	masked := prefix.Masked()
	if message.TargetIP == masked.Addr() || prefix.Bits() < 31 && message.TargetIP == ipv4Broadcast(masked) {
		return errors.New("ARP target cannot be the network or broadcast address")
	}
	return nil
}

func ipv4Broadcast(prefix netip.Prefix) netip.Addr {
	address := prefix.Addr().As4()
	value := binary.BigEndian.Uint32(address[:]) | ^uint32(0)>>prefix.Bits()
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], value)
	return netip.AddrFrom4(result)
}
