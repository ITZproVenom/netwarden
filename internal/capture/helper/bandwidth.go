package helper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/packet"
	"github.com/amdzy/NetWarden/internal/shaping"
)

const bandwidthRefreshInterval = time.Second

type bandwidthTarget struct {
	ip         netip.Addr
	addresses  []netip.Addr
	mac        net.HardwareAddr
	policy     shaping.Policy
	limited    bool
	continuous bool
}

type frameSenderFunc func(context.Context, []byte) error

func (f frameSenderFunc) Send(ctx context.Context, frame []byte) error { return f(ctx, frame) }

// bandwidthSession keeps packet contents inside the privileged helper. The
// parent process can install policies, but cannot request arbitrary IPv4
// transmission or inspect redirected payloads.
type bandwidthSession struct {
	localMAC  net.HardwareAddr
	localIP   netip.Addr
	gatewayIP netip.Addr
	prefix    netip.Prefix
	send      frameSenderFunc
	manager   *shaping.Manager
	forwarder *shaping.Forwarder

	mu            sync.RWMutex
	gatewayMAC    net.HardwareAddr
	localIPv6     netip.Addr
	routerIPv6    netip.Addr
	routerIPv6MAC net.HardwareAddr
	targets       map[string]bandwidthTarget
	isolated      map[string]bandwidthTarget
	cancel        context.CancelFunc
	done          chan error
	closeOnce     sync.Once
	closeErr      error
}

func (s *bandwidthSession) observeNDP(message packet.NDP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if bytes.Equal(message.SourceMAC, s.localMAC) && message.SourceIP.Is6() && !message.SourceIP.IsUnspecified() {
		s.localIPv6 = message.SourceIP
	}
	if message.Type == packet.ICMPv6RouterAdvertisement && message.SourceIP.Is6() && message.SourceIP.IsLinkLocalUnicast() &&
		validUnicastMAC(message.SourceMAC) && !bytes.Equal(message.SourceMAC, s.localMAC) {
		if len(s.routerIPv6MAC) == 0 || message.SourceIP == s.routerIPv6 && bytes.Equal(message.SourceMAC, s.routerIPv6MAC) {
			s.routerIPv6, s.routerIPv6MAC = message.SourceIP, append(net.HardwareAddr(nil), message.SourceMAC...)
		}
	}
}

func normalizeTargetAddresses(addresses []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(addresses))
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if address.IsValid() {
			if _, ok := seen[address]; !ok {
				seen[address] = struct{}{}
				result = append(result, address)
			}
		}
	}
	return result
}

func (s *bandwidthSession) setRoutes(ctx context.Context, addresses []netip.Addr, mac net.HardwareAddr, policy shaping.Policy) error {
	addresses = normalizeTargetAddresses(addresses)
	if len(addresses) == 0 {
		return errors.New("bandwidth target requires at least one address")
	}
	if err := s.set(ctx, addresses[0], mac, policy); err != nil {
		return err
	}
	return s.replaceRoutes(ctx, mac, addresses)
}

func (s *bandwidthSession) monitorRoutes(ctx context.Context, addresses []netip.Addr, mac net.HardwareAddr) error {
	addresses = normalizeTargetAddresses(addresses)
	if len(addresses) == 0 {
		return errors.New("bandwidth target requires at least one address")
	}
	if err := s.monitor(ctx, addresses[0], mac); err != nil {
		return err
	}
	return s.replaceRoutes(ctx, mac, addresses)
}

func (s *bandwidthSession) replaceRoutes(ctx context.Context, mac net.HardwareAddr, addresses []netip.Addr) error {
	key := mac.String()
	s.mu.RLock()
	target, ok := s.targets[key]
	s.mu.RUnlock()
	if !ok {
		return errors.New("bandwidth target state was lost")
	}
	wanted := make(map[netip.Addr]struct{}, len(addresses))
	removed := make([]netip.Addr, 0)
	for _, address := range addresses {
		wanted[address] = struct{}{}
	}
	for _, address := range target.addresses {
		if _, keep := wanted[address]; !keep {
			s.forwarder.RemoveRoute(address)
			if err := s.restoreAddress(ctx, target, address); err != nil {
				_ = s.forwarder.SetRoute(address, target.mac)
				return fmt.Errorf("restore removed route %s: %w", address, err)
			}
			removed = append(removed, address)
		}
	}
	installed := []netip.Addr{target.ip}
	for _, address := range addresses {
		if address == target.ip {
			continue
		}
		if err := s.validateTarget(address, mac); err != nil {
			s.rollbackRouteChange(target, installed[1:], removed)
			return err
		}
		if err := s.forwarder.SetRoute(address, mac); err != nil {
			s.rollbackRouteChange(target, installed[1:], removed)
			return err
		}
		installed = append(installed, address)
		target.addresses = append(target.addresses, address)
		if err := s.redirectAddress(ctx, target, address); err != nil {
			s.rollbackRouteChange(target, installed[1:], removed)
			return fmt.Errorf("redirect %s: %w", address, err)
		}
	}
	target.addresses = append([]netip.Addr(nil), addresses...)
	s.mu.Lock()
	s.targets[key] = target
	s.mu.Unlock()
	return nil
}

func (s *bandwidthSession) rollbackRouteChange(target bandwidthTarget, added, removed []netip.Addr) {
	for _, address := range added {
		s.forwarder.RemoveRoute(address)
		_ = s.restoreAddress(context.Background(), target, address)
	}
	for _, address := range removed {
		_ = s.forwarder.SetRoute(address, target.mac)
		_ = s.redirectAddress(context.Background(), target, address)
	}
}

func (s *bandwidthSession) removeRoutes(ctx context.Context, addresses []netip.Addr, mac net.HardwareAddr) error {
	return s.removeMode(ctx, firstOrRecorded(addresses, s.targetFor(mac)), mac, true)
}
func (s *bandwidthSession) removeMonitorRoutes(ctx context.Context, addresses []netip.Addr, mac net.HardwareAddr) error {
	return s.removeMode(ctx, firstOrRecorded(addresses, s.targetFor(mac)), mac, false)
}
func (s *bandwidthSession) targetFor(mac net.HardwareAddr) bandwidthTarget {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.targets[mac.String()]
}
func firstOrRecorded(addresses []netip.Addr, target bandwidthTarget) netip.Addr {
	if target.ip.IsValid() {
		return target.ip
	}
	if len(addresses) > 0 {
		return addresses[0]
	}
	return netip.Addr{}
}

func newBandwidthSession(ctx context.Context, localMAC net.HardwareAddr, localIP, gatewayIP netip.Addr, prefix netip.Prefix, send frameSenderFunc) (*bandwidthSession, error) {
	manager := shaping.NewManager()
	forwarder, err := shaping.NewForwarder(manager, send, shaping.ForwarderConfig{LocalMAC: localMAC})
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	session := &bandwidthSession{
		localMAC: append(net.HardwareAddr(nil), localMAC...), localIP: localIP, gatewayIP: gatewayIP,
		prefix: prefix, send: send, manager: manager, forwarder: forwarder,
		targets: make(map[string]bandwidthTarget), cancel: cancel, done: make(chan error, 1),
		isolated: make(map[string]bandwidthTarget),
	}
	go func() { session.done <- forwarder.Run(runCtx) }()
	go session.refresh(runCtx)
	return session, nil
}

func (s *bandwidthSession) observeGateway(mac net.HardwareAddr) {
	if !validUnicastMAC(mac) || bytes.Equal(mac, s.localMAC) {
		return
	}
	verified := append(net.HardwareAddr(nil), mac...)
	s.mu.Lock()
	s.gatewayMAC = verified
	s.mu.Unlock()
	_ = s.forwarder.SetGatewayMAC(verified)
}

func (s *bandwidthSession) submit(frame []byte) bool {
	err := s.forwarder.Submit(frame)
	return err == nil || errors.Is(err, shaping.ErrQueueFull)
}

func (s *bandwidthSession) dropIsolated(frame []byte) bool {
	source, destination, ok := frameAddresses(frame)
	if !ok {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, target := range s.isolated {
		for _, address := range target.addresses {
			if source == address || destination == address {
				return true
			}
		}
	}
	return false
}

func frameAddresses(frame []byte) (netip.Addr, netip.Addr, bool) {
	if len(frame) < packet.EthernetHeaderLen {
		return netip.Addr{}, netip.Addr{}, false
	}
	network := frame[packet.EthernetHeaderLen:]
	switch uint16(frame[12])<<8 | uint16(frame[13]) {
	case 0x0800:
		if len(network) < 20 || network[0]>>4 != 4 {
			return netip.Addr{}, netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(network[12:16])), netip.AddrFrom4([4]byte(network[16:20])), true
	case packet.EtherTypeIPv6:
		if len(network) < 40 || network[0]>>4 != 6 {
			return netip.Addr{}, netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(network[8:24])), netip.AddrFrom16([16]byte(network[24:40])), true
	default:
		return netip.Addr{}, netip.Addr{}, false
	}
}

func (s *bandwidthSession) isolateRoutes(ctx context.Context, addresses []netip.Addr, mac net.HardwareAddr, continuous bool) error {
	addresses = normalizeTargetAddresses(addresses)
	if len(addresses) == 0 {
		return errors.New("isolation target requires at least one address")
	}
	for _, address := range addresses {
		if err := s.validateTarget(address, mac); err != nil {
			return err
		}
	}
	key := mac.String()
	s.mu.RLock()
	_, forwarding := s.targets[key]
	previous, replacing := s.isolated[key]
	for otherKey, other := range s.isolated {
		if otherKey == key {
			continue
		}
		for _, address := range addresses {
			for _, occupied := range other.addresses {
				if address == occupied {
					s.mu.RUnlock()
					return errors.New("isolation target address is already assigned to another device")
				}
			}
		}
	}
	s.mu.RUnlock()
	if forwarding {
		return errors.New("remove bandwidth monitoring or limits before isolating the device")
	}
	target := bandwidthTarget{ip: addresses[0], addresses: append([]netip.Addr(nil), addresses...), mac: append(net.HardwareAddr(nil), mac...), continuous: continuous}
	s.mu.Lock()
	s.isolated[key] = target
	s.mu.Unlock()
	if err := s.redirect(ctx, target); err != nil {
		s.mu.Lock()
		if replacing {
			s.isolated[key] = previous
		} else {
			delete(s.isolated, key)
		}
		s.mu.Unlock()
		_ = s.restore(context.Background(), target)
		if replacing {
			_ = s.redirect(context.Background(), previous)
		}
		return fmt.Errorf("activate device isolation: %w", err)
	}
	if replacing {
		wanted := make(map[netip.Addr]struct{}, len(addresses))
		for _, address := range addresses {
			wanted[address] = struct{}{}
		}
		for _, address := range previous.addresses {
			if _, keep := wanted[address]; !keep {
				_ = s.restoreAddress(ctx, previous, address)
			}
		}
	}
	return nil
}

func (s *bandwidthSession) restoreIsolation(ctx context.Context, addresses []netip.Addr, mac net.HardwareAddr) error {
	key := mac.String()
	s.mu.Lock()
	target, found := s.isolated[key]
	if found {
		delete(s.isolated, key)
	}
	s.mu.Unlock()
	if !found {
		target = bandwidthTarget{ip: firstOrRecorded(addresses, bandwidthTarget{}), addresses: normalizeTargetAddresses(addresses), mac: append(net.HardwareAddr(nil), mac...)}
	}
	if len(target.addresses) == 0 {
		return nil
	}
	if err := s.restore(ctx, target); err != nil {
		if found {
			s.mu.Lock()
			s.isolated[key] = target
			s.mu.Unlock()
		}
		return err
	}
	return nil
}

func (s *bandwidthSession) set(ctx context.Context, ip netip.Addr, mac net.HardwareAddr, policy shaping.Policy) error {
	if err := s.validateTarget(ip, mac); err != nil {
		return err
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	s.mu.RLock()
	gatewayKnown := len(s.gatewayMAC) == 6
	s.mu.RUnlock()
	if !gatewayKnown {
		return errors.New("default gateway MAC has not been verified yet")
	}
	s.mu.RLock()
	previous, replacing := s.targets[mac.String()]
	if replacing && previous.ip != ip {
		s.mu.RUnlock()
		return errors.New("remove the existing bandwidth target before changing its IP")
	}
	for key, target := range s.targets {
		if key != mac.String() && target.ip == ip {
			s.mu.RUnlock()
			return errors.New("bandwidth target IP is already assigned to another device")
		}
	}
	s.mu.RUnlock()
	if err := s.manager.Set(mac, policy); err != nil {
		return err
	}
	if err := s.forwarder.SetRoute(ip, mac); err != nil {
		_ = s.manager.Remove(mac)
		return err
	}
	addresses := []netip.Addr{ip}
	if replacing {
		addresses = append([]netip.Addr(nil), previous.addresses...)
	}
	target := bandwidthTarget{ip: ip, addresses: addresses, mac: append(net.HardwareAddr(nil), mac...), policy: policy, limited: true}
	s.mu.Lock()
	s.targets[mac.String()] = target
	s.mu.Unlock()
	if err := s.redirect(ctx, target); err != nil {
		if replacing {
			if previous.limited {
				_ = s.manager.Set(previous.mac, previous.policy)
			} else {
				_ = s.manager.Remove(previous.mac)
				_ = s.manager.Track(previous.mac)
			}
			s.mu.Lock()
			s.targets[previous.mac.String()] = previous
			s.mu.Unlock()
		} else {
			s.removeState(target)
			_ = s.restore(context.Background(), target)
		}
		return fmt.Errorf("activate bandwidth path: %w", err)
	}
	return nil
}

func (s *bandwidthSession) remove(ctx context.Context, ip netip.Addr, mac net.HardwareAddr) error {
	return s.removeMode(ctx, ip, mac, true)
}

func (s *bandwidthSession) monitor(ctx context.Context, ip netip.Addr, mac net.HardwareAddr) error {
	if err := s.validateTarget(ip, mac); err != nil {
		return err
	}
	s.mu.RLock()
	gatewayKnown := len(s.gatewayMAC) == 6
	s.mu.RUnlock()
	if !gatewayKnown {
		return errors.New("default gateway MAC has not been verified yet")
	}
	s.mu.RLock()
	existing, found := s.targets[mac.String()]
	s.mu.RUnlock()
	if found {
		if existing.ip != ip {
			return errors.New("remove the existing forwarding target before changing its IP")
		}
		if existing.limited {
			if err := s.manager.SetUnrestricted(mac); err != nil {
				return err
			}
			existing.limited, existing.policy = false, shaping.Policy{}
			s.mu.Lock()
			s.targets[mac.String()] = existing
			s.mu.Unlock()
		}
		return nil
	}
	if err := s.manager.Track(mac); err != nil {
		return err
	}
	if err := s.forwarder.SetRoute(ip, mac); err != nil {
		_ = s.manager.Untrack(mac)
		return err
	}
	target := bandwidthTarget{ip: ip, addresses: []netip.Addr{ip}, mac: append(net.HardwareAddr(nil), mac...)}
	s.mu.Lock()
	s.targets[mac.String()] = target
	s.mu.Unlock()
	if err := s.redirect(ctx, target); err != nil {
		s.removeState(target)
		_ = s.restore(context.Background(), target)
		return fmt.Errorf("activate monitoring path: %w", err)
	}
	return nil
}

func (s *bandwidthSession) removeMonitor(ctx context.Context, ip netip.Addr, mac net.HardwareAddr) error {
	return s.removeMode(ctx, ip, mac, false)
}

func (s *bandwidthSession) removeMode(ctx context.Context, ip netip.Addr, mac net.HardwareAddr, limited bool) error {
	if err := s.validateTarget(ip, mac); err != nil {
		return err
	}
	s.mu.RLock()
	target, found := s.targets[mac.String()]
	if found && target.ip != ip {
		s.mu.RUnlock()
		return errors.New("bandwidth target identity does not match the active policy")
	}
	s.mu.RUnlock()
	if !found {
		return nil
	}
	if target.limited != limited {
		if limited {
			return errors.New("target is monitored without a bandwidth limit")
		}
		return errors.New("remove the bandwidth limit before stopping monitoring")
	}
	s.mu.Lock()
	delete(s.targets, mac.String())
	s.mu.Unlock()
	for _, address := range target.addresses {
		s.forwarder.RemoveRoute(address)
	}
	_ = s.manager.Remove(target.mac)
	if err := s.restore(ctx, target); err != nil {
		if target.limited {
			_ = s.manager.Set(target.mac, target.policy)
		} else {
			_ = s.manager.Track(target.mac)
		}
		for _, address := range target.addresses {
			_ = s.forwarder.SetRoute(address, target.mac)
		}
		s.mu.Lock()
		s.targets[target.mac.String()] = target
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *bandwidthSession) close() error {
	s.closeOnce.Do(func() { s.closeErr = s.closeActive() })
	return s.closeErr
}

func (s *bandwidthSession) closeActive() error {
	restoreCtx, cancelRestore := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelRestore()
	s.mu.Lock()
	targets := make([]bandwidthTarget, 0, len(s.targets))
	for _, target := range s.targets {
		targets = append(targets, target)
	}
	s.targets = make(map[string]bandwidthTarget)
	for _, target := range s.isolated {
		targets = append(targets, target)
	}
	s.isolated = make(map[string]bandwidthTarget)
	s.mu.Unlock()
	var result error
	for _, target := range targets {
		for _, address := range target.addresses {
			s.forwarder.RemoveRoute(address)
		}
		_ = s.manager.Remove(target.mac)
		result = errors.Join(result, s.restore(restoreCtx, target))
	}
	s.cancel()
	if err := <-s.done; err != nil && !errors.Is(err, context.Canceled) {
		result = errors.Join(result, err)
	}
	return result
}

func (s *bandwidthSession) refresh(ctx context.Context) {
	ticker := time.NewTicker(bandwidthRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.RLock()
			targets := make([]bandwidthTarget, 0, len(s.targets))
			for _, target := range s.targets {
				targets = append(targets, target)
			}
			s.mu.RUnlock()
			s.mu.RLock()
			for _, target := range s.isolated {
				if target.continuous {
					targets = append(targets, target)
				}
			}
			s.mu.RUnlock()
			for _, target := range targets {
				_ = s.redirect(ctx, target)
			}
		}
	}
}

func (s *bandwidthSession) redirect(ctx context.Context, target bandwidthTarget) error {
	var result error
	for _, address := range target.addresses {
		result = errors.Join(result, s.redirectAddress(ctx, target, address))
	}
	return result
}

func (s *bandwidthSession) redirectAddress(ctx context.Context, target bandwidthTarget, address netip.Addr) error {
	if address.Is6() {
		return s.ndpRedirect(ctx, target, address)
	}
	s.mu.RLock()
	gatewayMAC := append(net.HardwareAddr(nil), s.gatewayMAC...)
	s.mu.RUnlock()
	toDevice, err := arpReply(target.mac, s.localMAC, s.localMAC, s.gatewayIP, target.mac, target.ip)
	if err != nil {
		return err
	}
	toGateway, err := arpReply(gatewayMAC, s.localMAC, s.localMAC, target.ip, gatewayMAC, s.gatewayIP)
	if err != nil {
		return err
	}
	if err := s.send(ctx, toDevice); err != nil {
		return err
	}
	return s.send(ctx, toGateway)
}

func (s *bandwidthSession) restore(ctx context.Context, target bandwidthTarget) error {
	var result error
	for _, address := range target.addresses {
		result = errors.Join(result, s.restoreAddress(ctx, target, address))
	}
	return result
}

func (s *bandwidthSession) restoreAddress(ctx context.Context, target bandwidthTarget, address netip.Addr) error {
	if address.Is6() {
		return s.ndpRestore(ctx, target, address)
	}
	s.mu.RLock()
	gatewayMAC := append(net.HardwareAddr(nil), s.gatewayMAC...)
	s.mu.RUnlock()
	if len(gatewayMAC) != 6 {
		return errors.New("cannot restore bandwidth path without a verified gateway MAC")
	}
	toDevice, err := arpReply(target.mac, gatewayMAC, gatewayMAC, s.gatewayIP, target.mac, target.ip)
	if err != nil {
		return err
	}
	toGateway, err := arpReply(gatewayMAC, target.mac, target.mac, target.ip, gatewayMAC, s.gatewayIP)
	if err != nil {
		return err
	}
	var result error
	// Duplicate corrective announcements make shutdown restoration resilient to
	// a single dropped frame without extending helper shutdown materially.
	for range 2 {
		result = errors.Join(result, s.send(ctx, toDevice), s.send(ctx, toGateway))
	}
	return result
}

func (s *bandwidthSession) ndpRedirect(ctx context.Context, target bandwidthTarget, address netip.Addr) error {
	s.mu.RLock()
	localIP, routerIP, routerMAC := s.localIPv6, s.routerIPv6, append(net.HardwareAddr(nil), s.routerIPv6MAC...)
	s.mu.RUnlock()
	if !localIP.Is6() || !routerIP.Is6() || len(routerMAC) != 6 {
		return errors.New("verified IPv6 local and router identities are required")
	}
	toDevice, err := packet.MarshalNeighborAdvertisement(packet.NeighborAdvertisement{SourceIP: routerIP, DestinationIP: address, TargetIP: routerIP, SourceMAC: s.localMAC, DestinationMAC: target.mac, AdvertisedMAC: s.localMAC, Router: true, Solicited: true, Override: true})
	if err != nil {
		return err
	}
	toRouter, err := packet.MarshalNeighborAdvertisement(packet.NeighborAdvertisement{SourceIP: address, DestinationIP: routerIP, TargetIP: address, SourceMAC: s.localMAC, DestinationMAC: routerMAC, AdvertisedMAC: s.localMAC, Solicited: true, Override: true})
	if err != nil {
		return err
	}
	if err := s.send(ctx, toDevice); err != nil {
		return err
	}
	return s.send(ctx, toRouter)
}

func (s *bandwidthSession) ndpRestore(ctx context.Context, target bandwidthTarget, address netip.Addr) error {
	s.mu.RLock()
	routerIP, routerMAC := s.routerIPv6, append(net.HardwareAddr(nil), s.routerIPv6MAC...)
	s.mu.RUnlock()
	if !routerIP.Is6() || len(routerMAC) != 6 {
		return errors.New("cannot restore IPv6 path without a verified router identity")
	}
	toDevice, err := packet.MarshalNeighborAdvertisement(packet.NeighborAdvertisement{SourceIP: routerIP, DestinationIP: address, TargetIP: routerIP, SourceMAC: routerMAC, DestinationMAC: target.mac, AdvertisedMAC: routerMAC, Router: true, Solicited: true, Override: true})
	if err != nil {
		return err
	}
	toRouter, err := packet.MarshalNeighborAdvertisement(packet.NeighborAdvertisement{SourceIP: address, DestinationIP: routerIP, TargetIP: address, SourceMAC: target.mac, DestinationMAC: routerMAC, AdvertisedMAC: target.mac, Solicited: true, Override: true})
	if err != nil {
		return err
	}
	var result error
	for range 2 {
		result = errors.Join(result, s.send(ctx, toDevice), s.send(ctx, toRouter))
	}
	return result
}

func (s *bandwidthSession) removeState(target bandwidthTarget) {
	s.mu.Lock()
	delete(s.targets, target.mac.String())
	s.mu.Unlock()
	for _, address := range target.addresses {
		s.forwarder.RemoveRoute(address)
	}
	_ = s.manager.Remove(target.mac)
}

func (s *bandwidthSession) validateTarget(ip netip.Addr, mac net.HardwareAddr) error {
	masked := s.prefix.Masked()
	if ip.Is4() {
		if !masked.Contains(ip) || ip == s.localIP || ip == s.gatewayIP || ip == masked.Addr() || s.prefix.Bits() < 31 && ip == ipv4Broadcast(masked) {
			return errors.New("bandwidth target is outside the eligible local network")
		}
	} else if ip.Is6() {
		if ip.IsMulticast() || ip.IsUnspecified() || ip.IsLoopback() {
			return errors.New("bandwidth target is not an eligible IPv6 unicast address")
		}
		s.mu.RLock()
		local, router := s.localIPv6, s.routerIPv6
		s.mu.RUnlock()
		if !local.Is6() || !router.Is6() || ip == local || ip == router {
			return errors.New("verified IPv6 local and router identities are required")
		}
	} else {
		return errors.New("bandwidth target is outside the eligible local network")
	}
	if !validUnicastMAC(mac) || bytes.Equal(mac, s.localMAC) {
		return errors.New("bandwidth target requires a distinct unicast MAC")
	}
	s.mu.RLock()
	isGateway := bytes.Equal(mac, s.gatewayMAC)
	s.mu.RUnlock()
	if isGateway {
		return errors.New("the default gateway cannot be bandwidth limited")
	}
	return nil
}

func arpReply(destination, source, senderMAC net.HardwareAddr, senderIP netip.Addr, targetMAC net.HardwareAddr, targetIP netip.Addr) ([]byte, error) {
	return packet.MarshalARP(destination, source, packet.ARP{
		Operation: packet.ARPOpReply, SenderMAC: senderMAC, SenderIP: senderIP,
		TargetMAC: targetMAC, TargetIP: targetIP,
	})
}

func validUnicastMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 || mac[0]&1 != 0 {
		return false
	}
	for _, value := range mac {
		if value != 0 {
			return true
		}
	}
	return false
}
