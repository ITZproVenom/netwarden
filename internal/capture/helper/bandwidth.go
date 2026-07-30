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
	ip      netip.Addr
	mac     net.HardwareAddr
	policy  shaping.Policy
	limited bool
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

	mu         sync.RWMutex
	gatewayMAC net.HardwareAddr
	targets    map[string]bandwidthTarget
	cancel     context.CancelFunc
	done       chan error
	closeOnce  sync.Once
	closeErr   error
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
	target := bandwidthTarget{ip: ip, mac: append(net.HardwareAddr(nil), mac...), policy: policy, limited: true}
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
	target := bandwidthTarget{ip: ip, mac: append(net.HardwareAddr(nil), mac...)}
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
	s.forwarder.RemoveRoute(target.ip)
	_ = s.manager.Remove(target.mac)
	if err := s.restore(ctx, target); err != nil {
		if target.limited {
			_ = s.manager.Set(target.mac, target.policy)
		} else {
			_ = s.manager.Track(target.mac)
		}
		_ = s.forwarder.SetRoute(target.ip, target.mac)
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
	s.mu.Unlock()
	var result error
	for _, target := range targets {
		s.forwarder.RemoveRoute(target.ip)
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
			for _, target := range targets {
				_ = s.redirect(ctx, target)
			}
		}
	}
}

func (s *bandwidthSession) redirect(ctx context.Context, target bandwidthTarget) error {
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

func (s *bandwidthSession) removeState(target bandwidthTarget) {
	s.mu.Lock()
	delete(s.targets, target.mac.String())
	s.mu.Unlock()
	s.forwarder.RemoveRoute(target.ip)
	_ = s.manager.Remove(target.mac)
}

func (s *bandwidthSession) validateTarget(ip netip.Addr, mac net.HardwareAddr) error {
	masked := s.prefix.Masked()
	if !ip.Is4() || !masked.Contains(ip) || ip == s.localIP || ip == s.gatewayIP || ip == masked.Addr() || s.prefix.Bits() < 31 && ip == ipv4Broadcast(masked) {
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
