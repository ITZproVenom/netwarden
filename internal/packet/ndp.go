package packet

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
)

const (
	EtherTypeIPv6    = 0x86dd
	NextHeaderICMPv6 = 58
	NDPHopLimit      = 255

	ICMPv6RouterSolicitation    = 133
	ICMPv6RouterAdvertisement   = 134
	ICMPv6NeighborSolicitation  = 135
	ICMPv6NeighborAdvertisement = 136
)

var ErrMalformedNDP = errors.New("malformed Ethernet IPv6 neighbor-discovery frame")

// NDP is the validated identity-bearing subset of an ICMPv6 Neighbor
// Discovery message. Address selection remains a discovery-layer concern.
type NDP struct {
	Type      uint8
	SourceIP  netip.Addr
	TargetIP  netip.Addr
	SourceMAC net.HardwareAddr
}

// ParseNDP validates an Ethernet/IPv6 ICMPv6 Neighbor Discovery frame. This
// initial parser deliberately rejects extension headers: accepting them safely
// belongs in a reusable IPv6 extension-chain parser, not in NDP-specific code.
func ParseNDP(frame []byte) (NDP, error) {
	const ipv6HeaderLength = 40
	if len(frame) < EthernetHeaderLen+ipv6HeaderLength+8 ||
		binary.BigEndian.Uint16(frame[12:14]) != EtherTypeIPv6 {
		return NDP{}, ErrMalformedNDP
	}
	ipv6 := frame[EthernetHeaderLen:]
	if ipv6[0]>>4 != 6 || ipv6[6] != NextHeaderICMPv6 || ipv6[7] != NDPHopLimit {
		return NDP{}, ErrMalformedNDP
	}
	payloadLength := int(binary.BigEndian.Uint16(ipv6[4:6]))
	if payloadLength < 8 || len(ipv6) < ipv6HeaderLength+payloadLength {
		return NDP{}, ErrMalformedNDP
	}
	sourceIP := netip.AddrFrom16([16]byte(ipv6[8:24]))
	destinationIP := netip.AddrFrom16([16]byte(ipv6[24:40]))
	icmp := ipv6[ipv6HeaderLength : ipv6HeaderLength+payloadLength]
	if icmp[1] != 0 || !isNDPType(icmp[0]) || !validICMPv6Checksum(sourceIP, destinationIP, icmp) {
		return NDP{}, ErrMalformedNDP
	}

	message := NDP{Type: icmp[0], SourceIP: sourceIP, SourceMAC: append(net.HardwareAddr(nil), frame[6:12]...)}
	optionOffset := 8
	switch message.Type {
	case ICMPv6RouterAdvertisement:
		if len(icmp) < 16 {
			return NDP{}, ErrMalformedNDP
		}
		optionOffset = 16
	case ICMPv6NeighborSolicitation, ICMPv6NeighborAdvertisement:
		if len(icmp) < 24 {
			return NDP{}, ErrMalformedNDP
		}
		message.TargetIP = netip.AddrFrom16([16]byte(icmp[8:24]))
		if !message.TargetIP.Is6() || message.TargetIP.IsMulticast() || message.TargetIP.IsUnspecified() {
			return NDP{}, ErrMalformedNDP
		}
		optionOffset = 24
	}

	for optionOffset < len(icmp) {
		if len(icmp)-optionOffset < 2 || icmp[optionOffset+1] == 0 {
			return NDP{}, ErrMalformedNDP
		}
		optionLength := int(icmp[optionOffset+1]) * 8
		if optionLength > len(icmp)-optionOffset {
			return NDP{}, ErrMalformedNDP
		}
		optionType := icmp[optionOffset]
		if (optionType == 1 || optionType == 2) && optionLength >= 8 {
			message.SourceMAC = append(net.HardwareAddr(nil), icmp[optionOffset+2:optionOffset+8]...)
		}
		optionOffset += optionLength
	}
	if !validNDPUnicastMAC(message.SourceMAC) {
		return NDP{}, ErrMalformedNDP
	}
	return message, nil
}

func isNDPType(value uint8) bool {
	return value >= ICMPv6RouterSolicitation && value <= ICMPv6NeighborAdvertisement
}

func validNDPUnicastMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return false
	}
	for _, octet := range mac {
		if octet != 0 {
			return true
		}
	}
	return false
}

func validICMPv6Checksum(source, destination netip.Addr, payload []byte) bool {
	sourceBytes, destinationBytes := source.As16(), destination.As16()
	var sum uint32
	sum = checksumBytes(sum, sourceBytes[:])
	sum = checksumBytes(sum, destinationBytes[:])
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	sum = checksumBytes(sum, length[:])
	sum += NextHeaderICMPv6
	sum = checksumBytes(sum, payload)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum) == 0xffff
}

func checksumBytes(sum uint32, value []byte) uint32 {
	for len(value) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(value[:2]))
		value = value[2:]
	}
	if len(value) == 1 {
		sum += uint32(value[0]) << 8
	}
	return sum
}
