// Package packet encodes and decodes the small subset of Ethernet and ARP
// needed by NetWarden. It intentionally has no capture-driver dependency.
package packet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

const (
	EthernetHeaderLen = 14
	ARPHeaderLen      = 28
	EtherTypeARP      = 0x0806
	arpHardwareEther  = 1
	arpProtocolIPv4   = 0x0800
	ARPOpRequest      = 1
	ARPOpReply        = 2
)

var ErrMalformedARP = errors.New("malformed Ethernet ARP frame")

// ARP describes an Ethernet/IPv4 ARP message.
type ARP struct {
	Operation uint16
	SenderMAC net.HardwareAddr
	SenderIP  netip.Addr
	TargetMAC net.HardwareAddr
	TargetIP  netip.Addr
}

// MarshalARP builds an Ethernet frame containing an IPv4 ARP message.
func MarshalARP(destination, source net.HardwareAddr, message ARP) ([]byte, error) {
	if err := validateMAC(destination); err != nil {
		return nil, fmt.Errorf("destination MAC: %w", err)
	}
	if err := validateMAC(source); err != nil {
		return nil, fmt.Errorf("source MAC: %w", err)
	}
	if err := validateARP(message); err != nil {
		return nil, err
	}

	frame := make([]byte, EthernetHeaderLen+ARPHeaderLen)
	copy(frame[0:6], destination)
	copy(frame[6:12], source)
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeARP)

	arp := frame[EthernetHeaderLen:]
	binary.BigEndian.PutUint16(arp[0:2], arpHardwareEther)
	binary.BigEndian.PutUint16(arp[2:4], arpProtocolIPv4)
	arp[4], arp[5] = 6, 4
	binary.BigEndian.PutUint16(arp[6:8], message.Operation)
	copy(arp[8:14], message.SenderMAC)
	senderIP := message.SenderIP.As4()
	copy(arp[14:18], senderIP[:])
	copy(arp[18:24], message.TargetMAC)
	targetIP := message.TargetIP.As4()
	copy(arp[24:28], targetIP[:])
	return frame, nil
}

// ParseARP parses a complete Ethernet frame containing an Ethernet/IPv4 ARP
// message. Copies are returned so callers can safely reuse capture buffers.
func ParseARP(frame []byte) (ARP, error) {
	if len(frame) < EthernetHeaderLen+ARPHeaderLen {
		return ARP{}, ErrMalformedARP
	}
	if binary.BigEndian.Uint16(frame[12:14]) != EtherTypeARP {
		return ARP{}, ErrMalformedARP
	}
	arp := frame[EthernetHeaderLen:]
	if binary.BigEndian.Uint16(arp[0:2]) != arpHardwareEther ||
		binary.BigEndian.Uint16(arp[2:4]) != arpProtocolIPv4 ||
		arp[4] != 6 || arp[5] != 4 {
		return ARP{}, ErrMalformedARP
	}

	return ARP{
		Operation: binary.BigEndian.Uint16(arp[6:8]),
		SenderMAC: append(net.HardwareAddr(nil), arp[8:14]...),
		SenderIP:  netip.AddrFrom4([4]byte(arp[14:18])),
		TargetMAC: append(net.HardwareAddr(nil), arp[18:24]...),
		TargetIP:  netip.AddrFrom4([4]byte(arp[24:28])),
	}, nil
}

func validateARP(message ARP) error {
	if message.Operation != ARPOpRequest && message.Operation != ARPOpReply {
		return fmt.Errorf("unsupported ARP operation %d", message.Operation)
	}
	if err := validateMAC(message.SenderMAC); err != nil {
		return fmt.Errorf("sender MAC: %w", err)
	}
	if err := validateMAC(message.TargetMAC); err != nil {
		return fmt.Errorf("target MAC: %w", err)
	}
	if !message.SenderIP.Is4() || !message.TargetIP.Is4() {
		return errors.New("ARP addresses must be IPv4")
	}
	return nil
}

func validateMAC(mac net.HardwareAddr) error {
	if len(mac) != 6 {
		return fmt.Errorf("expected 6 bytes, got %d", len(mac))
	}
	return nil
}
