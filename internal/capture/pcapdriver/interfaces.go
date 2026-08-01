package pcapdriver

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"

	"github.com/gopacket/gopacket/pcap"
)

var (
	ErrInterfaceNotFound = errors.New("capture interface not found")
	ErrSelectionRequired = errors.New("capture interface selection is required")
)

type Interface struct {
	Name        string
	Description string
	SystemName  string
	MAC         net.HardwareAddr
	Prefixes    []netip.Prefix
}

func ListInterfaces() ([]Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("list pcap devices: %w", err)
	}
	system, err := systemInterfacesByAddress()
	if err != nil {
		return nil, err
	}

	interfaces := make([]Interface, 0, len(devices))
	for _, candidate := range devices {
		info := Interface{Name: candidate.Name, Description: candidate.Description}
		seenPrefix := make(map[netip.Prefix]struct{})
		for _, address := range candidate.Addresses {
			ip, ok := netip.AddrFromSlice(address.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			bits, total := address.Netmask.Size()
			if bits < 0 || total != ip.BitLen() {
				continue
			}
			prefix := netip.PrefixFrom(ip, bits)
			if _, exists := seenPrefix[prefix]; !exists {
				info.Prefixes = append(info.Prefixes, prefix)
				seenPrefix[prefix] = struct{}{}
			}
			if matched, exists := system[ip]; exists {
				info.SystemName = matched.name
				info.MAC = append(net.HardwareAddr(nil), matched.mac...)
			}
		}
		if len(info.Prefixes) > 0 {
			interfaces = append(interfaces, info)
		}
	}
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Name < interfaces[j].Name })
	return interfaces, nil
}

// SelectInterface finds an explicitly named pcap or system interface. Without
// a name it succeeds only when exactly one usable non-loopback interface is
// available, avoiding unreliable gateway-name heuristics.
func SelectInterface(interfaces []Interface, requested string) (Interface, error) {
	if requested != "" {
		for _, candidate := range interfaces {
			if candidate.Name == requested || candidate.SystemName == requested {
				return candidate, nil
			}
		}
		return Interface{}, fmt.Errorf("%w: %s", ErrInterfaceNotFound, requested)
	}

	usable := make([]Interface, 0, len(interfaces))
	for _, candidate := range interfaces {
		if len(candidate.MAC) != 6 {
			continue
		}
		for _, prefix := range candidate.Prefixes {
			ip := prefix.Addr()
			if ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
				usable = append(usable, candidate)
				break
			}
		}
	}
	if len(usable) == 1 {
		return usable[0], nil
	}
	return Interface{}, fmt.Errorf("%w: found %d usable interfaces", ErrSelectionRequired, len(usable))
}

type systemInterface struct {
	name string
	mac  net.HardwareAddr
}

func systemInterfacesByAddress() (map[netip.Addr]systemInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list system interfaces: %w", err)
	}
	result := make(map[netip.Addr]systemInterface)
	for _, candidate := range interfaces {
		addresses, err := candidate.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				continue
			}
			result[prefix.Addr().Unmap()] = systemInterface{
				name: candidate.Name,
				mac:  append(net.HardwareAddr(nil), candidate.HardwareAddr...),
			}
		}
	}
	return result, nil
}
