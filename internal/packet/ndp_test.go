package packet

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

func TestParseNDPNeighborAdvertisement(t *testing.T) {
	source := netip.MustParseAddr("fe80::20c:29ff:fe12:3456")
	destination := netip.MustParseAddr("ff02::1")
	mac, _ := net.ParseMAC("02:0c:29:12:34:56")
	frame := ndpTestFrame(t, ICMPv6NeighborAdvertisement, source, destination, source, mac)

	message, err := ParseNDP(frame)
	if err != nil {
		t.Fatal(err)
	}
	if message.Type != ICMPv6NeighborAdvertisement || message.SourceIP != source ||
		message.TargetIP != source || message.SourceMAC.String() != mac.String() {
		t.Fatalf("unexpected NDP message: %#v", message)
	}
}

func TestParseNDPRejectsInvalidHopLimitAndChecksum(t *testing.T) {
	source := netip.MustParseAddr("fe80::2")
	destination := netip.MustParseAddr("ff02::1")
	mac, _ := net.ParseMAC("02:00:00:00:00:02")

	badHopLimit := ndpTestFrame(t, ICMPv6NeighborAdvertisement, source, destination, source, mac)
	badHopLimit[EthernetHeaderLen+7] = 64
	if _, err := ParseNDP(badHopLimit); err == nil {
		t.Fatal("accepted NDP message with non-link-local hop limit")
	}

	badChecksum := ndpTestFrame(t, ICMPv6NeighborAdvertisement, source, destination, source, mac)
	badChecksum[len(badChecksum)-1] ^= 0xff
	if _, err := ParseNDP(badChecksum); err == nil {
		t.Fatal("accepted NDP message with invalid checksum")
	}
}

func ndpTestFrame(t *testing.T, messageType uint8, source, destination, target netip.Addr, mac net.HardwareAddr) []byte {
	t.Helper()
	icmp := make([]byte, 32)
	icmp[0] = messageType
	copy(icmp[8:24], target.AsSlice())
	icmp[24], icmp[25] = 2, 1
	copy(icmp[26:32], mac)

	frame := make([]byte, EthernetHeaderLen+40+len(icmp))
	copy(frame[:6], []byte{0x33, 0x33, 0, 0, 0, 1})
	copy(frame[6:12], mac)
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeIPv6)
	ipv6 := frame[EthernetHeaderLen:]
	ipv6[0] = 0x60
	binary.BigEndian.PutUint16(ipv6[4:6], uint16(len(icmp)))
	ipv6[6], ipv6[7] = NextHeaderICMPv6, NDPHopLimit
	copy(ipv6[8:24], source.AsSlice())
	copy(ipv6[24:40], destination.AsSlice())
	copy(ipv6[40:], icmp)

	payload := ipv6[40:]
	var sum uint32
	sourceBytes, destinationBytes := source.As16(), destination.As16()
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
	binary.BigEndian.PutUint16(payload[2:4], ^uint16(sum))
	return frame
}
