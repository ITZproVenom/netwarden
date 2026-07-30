package shaping

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

var (
	ErrFrameNotManaged  = errors.New("frame does not belong to a managed shaping route")
	ErrQueueFull        = errors.New("shaping queue is full")
	ErrForwarderStopped = errors.New("shaping forwarder has stopped")
)

const (
	ethernetHeaderLength = 14
	etherTypeIPv4        = 0x0800
	defaultQueueCapacity = 256
	maximumQueueCapacity = 8192
)

type FrameSender interface {
	Send(context.Context, []byte) error
}

type ForwarderConfig struct {
	LocalMAC      net.HardwareAddr
	GatewayMAC    net.HardwareAddr
	QueueCapacity int
}

type ForwarderStats struct {
	Accepted        uint64
	Forwarded       uint64
	QueueDrops      uint64
	CanceledDrops   uint64
	SendErrors      uint64
	UnmanagedFrames uint64
}

type queuedFrame struct {
	data      []byte
	deviceMAC net.HardwareAddr
	direction Direction
}

// Forwarder handles only IPv4 frames that have already been redirected to the
// local host. ARP redirection and packet capture remain platform concerns.
type Forwarder struct {
	manager    *Manager
	sender     FrameSender
	localMAC   net.HardwareAddr
	identityMu sync.RWMutex
	gatewayMAC net.HardwareAddr
	upload     chan queuedFrame
	download   chan queuedFrame

	routesMu sync.RWMutex
	routes   map[netip.Addr]net.HardwareAddr
	runMu    sync.Mutex
	running  bool
	stopped  bool

	accepted        atomic.Uint64
	forwarded       atomic.Uint64
	queueDrops      atomic.Uint64
	canceledDrops   atomic.Uint64
	sendErrors      atomic.Uint64
	unmanagedFrames atomic.Uint64
	errors          chan error
}

func NewForwarder(manager *Manager, sender FrameSender, config ForwarderConfig) (*Forwarder, error) {
	if manager == nil {
		return nil, errors.New("shaping manager is required")
	}
	if sender == nil {
		return nil, errors.New("frame sender is required")
	}
	localMAC, err := copyUnicastMAC(config.LocalMAC, "local")
	if err != nil {
		return nil, err
	}
	var gatewayMAC net.HardwareAddr
	if len(config.GatewayMAC) != 0 {
		gatewayMAC, err = copyUnicastMAC(config.GatewayMAC, "gateway")
		if err != nil {
			return nil, err
		}
	}
	capacity := config.QueueCapacity
	if capacity == 0 {
		capacity = defaultQueueCapacity
	}
	if capacity < 1 || capacity > maximumQueueCapacity {
		return nil, fmt.Errorf("queue capacity must be between 1 and %d", maximumQueueCapacity)
	}
	return &Forwarder{
		manager: manager, sender: sender, localMAC: localMAC, gatewayMAC: gatewayMAC,
		upload: make(chan queuedFrame, capacity), download: make(chan queuedFrame, capacity),
		routes: make(map[netip.Addr]net.HardwareAddr), errors: make(chan error, 32),
	}, nil
}

// SetGatewayMAC updates the verified default-gateway identity. Until one is
// supplied, redirected frames are deliberately rejected rather than guessed.
func (f *Forwarder) SetGatewayMAC(mac net.HardwareAddr) error {
	verified, err := copyUnicastMAC(mac, "gateway")
	if err != nil {
		return err
	}
	f.identityMu.Lock()
	f.gatewayMAC = verified
	f.identityMu.Unlock()
	return nil
}

func (f *Forwarder) SetRoute(ip netip.Addr, mac net.HardwareAddr) error {
	if !ip.Is4() || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("shaping route requires a unicast IPv4 address")
	}
	key, err := normalizeDeviceMAC(mac)
	if err != nil {
		return err
	}
	canonical, _ := net.ParseMAC(key)
	f.routesMu.Lock()
	f.routes[ip] = append(net.HardwareAddr(nil), canonical...)
	f.routesMu.Unlock()
	return nil
}

func (f *Forwarder) RemoveRoute(ip netip.Addr) {
	f.routesMu.Lock()
	delete(f.routes, ip)
	f.routesMu.Unlock()
}

// Submit classifies and copies a frame without blocking packet capture. A full
// directional queue drops the new frame and returns ErrQueueFull.
func (f *Forwarder) Submit(frame []byte) error {
	queued, err := f.classify(frame)
	if err != nil {
		f.unmanagedFrames.Add(1)
		return err
	}
	queue := f.upload
	if queued.direction == Download {
		queue = f.download
	}
	f.runMu.Lock()
	defer f.runMu.Unlock()
	if f.stopped {
		return ErrForwarderStopped
	}
	select {
	case queue <- queued:
		f.accepted.Add(1)
		return nil
	default:
		f.queueDrops.Add(1)
		return ErrQueueFull
	}
}

// Run owns one worker per direction so a slow download cannot block upload
// forwarding. It is intentionally one-shot.
func (f *Forwarder) Run(ctx context.Context) error {
	f.runMu.Lock()
	if f.running || f.stopped {
		f.runMu.Unlock()
		return errors.New("shaping forwarder is already running or has stopped")
	}
	f.running = true
	f.runMu.Unlock()
	var workers sync.WaitGroup
	workers.Add(2)
	go f.runDirection(ctx, f.upload, &workers)
	go f.runDirection(ctx, f.download, &workers)
	<-ctx.Done()
	workers.Wait()
	f.runMu.Lock()
	f.running = false
	f.stopped = true
	f.runMu.Unlock()
	f.drainCanceled(f.upload)
	f.drainCanceled(f.download)
	return ctx.Err()
}

func (f *Forwarder) Errors() <-chan error { return f.errors }

func (f *Forwarder) Stats() ForwarderStats {
	return ForwarderStats{
		Accepted: f.accepted.Load(), Forwarded: f.forwarded.Load(), QueueDrops: f.queueDrops.Load(),
		CanceledDrops: f.canceledDrops.Load(), SendErrors: f.sendErrors.Load(), UnmanagedFrames: f.unmanagedFrames.Load(),
	}
}

func (f *Forwarder) classify(frame []byte) (queuedFrame, error) {
	if len(frame) < ethernetHeaderLength+20 || binary.BigEndian.Uint16(frame[12:14]) != etherTypeIPv4 {
		return queuedFrame{}, ErrFrameNotManaged
	}
	versionLength := frame[ethernetHeaderLength]
	headerLength := int(versionLength&0x0f) * 4
	if versionLength>>4 != 4 || headerLength < 20 || len(frame) < ethernetHeaderLength+headerLength {
		return queuedFrame{}, ErrFrameNotManaged
	}
	totalLength := int(binary.BigEndian.Uint16(frame[ethernetHeaderLength+2 : ethernetHeaderLength+4]))
	if totalLength < headerLength || ethernetHeaderLength+totalLength > len(frame) {
		return queuedFrame{}, ErrFrameNotManaged
	}
	destination, source := net.HardwareAddr(frame[:6]), net.HardwareAddr(frame[6:12])
	if !bytes.Equal(destination, f.localMAC) {
		return queuedFrame{}, ErrFrameNotManaged
	}
	f.identityMu.RLock()
	gatewayMAC := append(net.HardwareAddr(nil), f.gatewayMAC...)
	f.identityMu.RUnlock()
	if len(gatewayMAC) != 6 {
		return queuedFrame{}, ErrFrameNotManaged
	}
	result := queuedFrame{data: append([]byte(nil), frame[:ethernetHeaderLength+totalLength]...)}
	if bytes.Equal(source, gatewayMAC) {
		var destinationIPBytes [4]byte
		copy(destinationIPBytes[:], frame[ethernetHeaderLength+16:ethernetHeaderLength+20])
		destinationIP := netip.AddrFrom4(destinationIPBytes)
		f.routesMu.RLock()
		deviceMAC := append(net.HardwareAddr(nil), f.routes[destinationIP]...)
		f.routesMu.RUnlock()
		if !f.manager.Has(deviceMAC) {
			return queuedFrame{}, ErrFrameNotManaged
		}
		result.deviceMAC, result.direction = deviceMAC, Download
		copy(result.data[:6], deviceMAC)
		copy(result.data[6:12], f.localMAC)
		return result, nil
	}
	if !f.manager.Has(source) {
		return queuedFrame{}, ErrFrameNotManaged
	}
	result.deviceMAC, result.direction = append(net.HardwareAddr(nil), source...), Upload
	copy(result.data[:6], gatewayMAC)
	copy(result.data[6:12], f.localMAC)
	return result, nil
}

func (f *Forwarder) runDirection(ctx context.Context, queue <-chan queuedFrame, workers *sync.WaitGroup) {
	defer workers.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case frame := <-queue:
			if err := f.manager.Wait(ctx, frame.deviceMAC, frame.direction, len(frame.data)); err != nil {
				f.canceledDrops.Add(1)
				continue
			}
			if !f.manager.Has(frame.deviceMAC) {
				f.canceledDrops.Add(1)
				continue
			}
			if err := f.sender.Send(ctx, frame.data); err != nil {
				f.sendErrors.Add(1)
				select {
				case f.errors <- err:
				default:
				}
				continue
			}
			f.forwarded.Add(1)
		}
	}
}

func (f *Forwarder) drainCanceled(queue <-chan queuedFrame) {
	for {
		select {
		case <-queue:
			f.canceledDrops.Add(1)
		default:
			return
		}
	}
}

func copyUnicastMAC(mac net.HardwareAddr, label string) (net.HardwareAddr, error) {
	if _, err := normalizeDeviceMAC(mac); err != nil {
		return nil, fmt.Errorf("%s MAC: %w", label, err)
	}
	return append(net.HardwareAddr(nil), mac...), nil
}
