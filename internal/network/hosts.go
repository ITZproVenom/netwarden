// Package network contains IP network calculations used by discovery.
package network

import (
	"errors"
	"fmt"
	"net/netip"
)

var (
	ErrNotIPv4      = errors.New("prefix is not IPv4")
	ErrHostLimit    = errors.New("subnet exceeds host limit")
	ErrInvalidLimit = errors.New("host limit must be positive")
)

// IPv4Hosts returns usable addresses in prefix. For conventional subnets it
// excludes the network and broadcast addresses. /31 and /32 prefixes retain
// all addresses because neither has a conventional broadcast host range.
//
// max protects callers from accidentally scanning very large networks.
func IPv4Hosts(prefix netip.Prefix, max int) ([]netip.Addr, error) {
	if max <= 0 {
		return nil, ErrInvalidLimit
	}
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return nil, ErrNotIPv4
	}

	prefix = prefix.Masked()
	bits := prefix.Bits()
	hostBits := 32 - bits
	count := uint64(1) << hostBits
	if bits <= 30 {
		count -= 2
	}
	if count > uint64(max) {
		return nil, fmt.Errorf("%w: %d addresses (limit %d)", ErrHostLimit, count, max)
	}

	first := ipv4Uint32(prefix.Addr())
	if bits <= 30 {
		first++
	}

	hosts := make([]netip.Addr, 0, int(count))
	for offset := uint64(0); offset < count; offset++ {
		hosts = append(hosts, uint32IPv4(first+uint32(offset)))
	}
	return hosts, nil
}

func ipv4Uint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func uint32IPv4(value uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}
