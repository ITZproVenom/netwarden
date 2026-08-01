package shaping

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
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
	etherTypeIPv6        = 0x86dd
	defaultQueueCapacity = 4096
	maximumQueueCapacity = 8192
	defaultQueueBytes    = 6 * 1024 * 1024
	maximumQueueBytes    = 64 * 1024 * 1024
)

type FrameSender interface {
	Send(context.Context, []byte) error
}

type ForwarderConfig struct {
	LocalMAC      net.HardwareAddr
	GatewayMAC    net.HardwareAddr
	QueueCapacity int
	QueueBytes    int
}

type ForwarderStats struct {
	Accepted           uint64
	Forwarded          uint64
	QueueDrops         uint64
	UploadQueueDrops   uint64
	DownloadQueueDrops uint64
	MonitorQueueDrops  uint64
	LimitedQueueDrops  uint64
	CanceledDrops      uint64
	SendErrors         uint64
	UnmanagedFrames    uint64
	QueueCapacity      int
	UploadQueueDepth   int
	DownloadQueueDepth int
	PeakUploadDepth    uint64
	PeakDownloadDepth  uint64
	QueueByteCapacity  int64
	UploadQueueBytes   int64
	DownloadQueueBytes int64
	PeakUploadBytes    uint64
	PeakDownloadBytes  uint64
	DeviceQueueDrops   []DeviceQueueDropStats
}

type DeviceQueueDropStats struct {
	MAC           string
	UploadDrops   uint64
	DownloadDrops uint64
}

type DeviceTrafficStats struct {
	MAC             string
	UploadPackets   uint64
	UploadBytes     uint64
	DownloadPackets uint64
	DownloadBytes   uint64
}

type queuedFrame struct {
	data      []byte
	deviceMAC net.HardwareAddr
	deviceKey string
	direction Direction
	limited   bool
}

type forwardingRoute struct {
	mac net.HardwareAddr
	key string
}

// directionalQueue bounds bursts by both frame count and memory. Packet
// capture never waits for space, avoiding a libpcap stall that would merely
// move packet loss into an opaque kernel buffer.
type directionalQueue struct {
	frames    chan queuedFrame
	maxFrames int64
	maxBytes  int64
	count     atomic.Int64
	bytes     atomic.Int64
	peakBytes atomic.Uint64
}

func newDirectionalQueue(frameCapacity, byteCapacity int) directionalQueue {
	return directionalQueue{frames: make(chan queuedFrame, frameCapacity), maxFrames: int64(frameCapacity), maxBytes: int64(byteCapacity)}
}

func (q *directionalQueue) enqueue(frame queuedFrame) bool {
	for current := q.count.Load(); ; current = q.count.Load() {
		if current+1 > q.maxFrames {
			return false
		}
		if q.count.CompareAndSwap(current, current+1) {
			break
		}
	}
	size := int64(len(frame.data))
	for current := q.bytes.Load(); ; current = q.bytes.Load() {
		if current+size > q.maxBytes || !q.bytes.CompareAndSwap(current, current+size) {
			if current+size > q.maxBytes {
				q.count.Add(-1)
				return false
			}
			continue
		}
		break
	}
	select {
	case q.frames <- frame:
		updatePeak(&q.peakBytes, int(q.bytes.Load()))
		return true
	default:
		q.count.Add(-1)
		q.bytes.Add(-size)
		return false
	}
}

func (q *directionalQueue) release(frame queuedFrame) {
	q.count.Add(-1)
	q.bytes.Add(-int64(len(frame.data)))
}

// Forwarder handles only IPv4 frames that have already been redirected to the
// local host. ARP redirection and packet capture remain platform concerns.
type Forwarder struct {
	manager    *Manager
	sender     FrameSender
	localMAC   net.HardwareAddr
	identityMu sync.RWMutex
	gatewayMAC net.HardwareAddr
	upload     directionalQueue
	download   directionalQueue

	routesMu sync.RWMutex
	routes   map[netip.Addr]forwardingRoute
	runMu    sync.Mutex
	running  bool
	stopped  bool

	accepted           atomic.Uint64
	forwarded          atomic.Uint64
	queueDrops         atomic.Uint64
	uploadQueueDrops   atomic.Uint64
	downloadQueueDrops atomic.Uint64
	monitorQueueDrops  atomic.Uint64
	limitedQueueDrops  atomic.Uint64
	peakUploadDepth    atomic.Uint64
	peakDownloadDepth  atomic.Uint64
	canceledDrops      atomic.Uint64
	sendErrors         atomic.Uint64
	unmanagedFrames    atomic.Uint64
	errors             chan error
	trafficMu          sync.RWMutex
	traffic            map[string]DeviceTrafficStats
	dropMu             sync.RWMutex
	deviceDrops        map[string]DeviceQueueDropStats
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
	byteCapacity := config.QueueBytes
	if byteCapacity == 0 {
		byteCapacity = defaultQueueBytes
	}
	if byteCapacity < 1 || byteCapacity > maximumQueueBytes {
		return nil, fmt.Errorf("queue byte capacity must be between 1 and %d", maximumQueueBytes)
	}
	return &Forwarder{
		manager: manager, sender: sender, localMAC: localMAC, gatewayMAC: gatewayMAC,
		upload: newDirectionalQueue(capacity, byteCapacity), download: newDirectionalQueue(capacity, byteCapacity),
		routes: make(map[netip.Addr]forwardingRoute), errors: make(chan error, 32), traffic: make(map[string]DeviceTrafficStats),
		deviceDrops: make(map[string]DeviceQueueDropStats),
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
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("shaping route requires a unicast IP address")
	}
	key, err := normalizeDeviceMAC(mac)
	if err != nil {
		return err
	}
	canonical, _ := net.ParseMAC(key)
	f.routesMu.Lock()
	f.routes[ip] = forwardingRoute{mac: append(net.HardwareAddr(nil), canonical...), key: key}
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
	queue := &f.upload
	if queued.direction == Download {
		queue = &f.download
	}
	f.runMu.Lock()
	defer f.runMu.Unlock()
	if f.stopped {
		return ErrForwarderStopped
	}
	if queue.enqueue(queued) {
		f.accepted.Add(1)
		if queued.direction == Download {
			updatePeak(&f.peakDownloadDepth, int(queue.count.Load()))
		} else {
			updatePeak(&f.peakUploadDepth, int(queue.count.Load()))
		}
		return nil
	}
	f.recordQueueDrop(queued)
	return ErrQueueFull
}

// Run owns a fair per-device scheduler and a single serialized transmitter. It
// is intentionally one-shot.
func (f *Forwarder) Run(ctx context.Context) error {
	f.runMu.Lock()
	if f.running || f.stopped {
		f.runMu.Unlock()
		return errors.New("shaping forwarder is already running or has stopped")
	}
	f.running = true
	f.runMu.Unlock()
	newPacketScheduler(f).run(ctx)
	f.runMu.Lock()
	f.running = false
	f.stopped = true
	f.runMu.Unlock()
	f.drainCanceled(&f.upload)
	f.drainCanceled(&f.download)
	return ctx.Err()
}

func (f *Forwarder) Errors() <-chan error { return f.errors }

func (f *Forwarder) Stats() ForwarderStats {
	stats := ForwarderStats{
		Accepted: f.accepted.Load(), Forwarded: f.forwarded.Load(), QueueDrops: f.queueDrops.Load(),
		UploadQueueDrops: f.uploadQueueDrops.Load(), DownloadQueueDrops: f.downloadQueueDrops.Load(),
		MonitorQueueDrops: f.monitorQueueDrops.Load(), LimitedQueueDrops: f.limitedQueueDrops.Load(),
		CanceledDrops: f.canceledDrops.Load(), SendErrors: f.sendErrors.Load(), UnmanagedFrames: f.unmanagedFrames.Load(),
		QueueCapacity: cap(f.upload.frames), UploadQueueDepth: int(f.upload.count.Load()), DownloadQueueDepth: int(f.download.count.Load()),
		PeakUploadDepth: f.peakUploadDepth.Load(), PeakDownloadDepth: f.peakDownloadDepth.Load(),
		QueueByteCapacity: f.upload.maxBytes, UploadQueueBytes: f.upload.bytes.Load(), DownloadQueueBytes: f.download.bytes.Load(),
		PeakUploadBytes: f.upload.peakBytes.Load(), PeakDownloadBytes: f.download.peakBytes.Load(),
	}
	f.dropMu.RLock()
	stats.DeviceQueueDrops = make([]DeviceQueueDropStats, 0, len(f.deviceDrops))
	for _, drops := range f.deviceDrops {
		stats.DeviceQueueDrops = append(stats.DeviceQueueDrops, drops)
	}
	f.dropMu.RUnlock()
	sort.Slice(stats.DeviceQueueDrops, func(i, j int) bool { return stats.DeviceQueueDrops[i].MAC < stats.DeviceQueueDrops[j].MAC })
	return stats
}

func (f *Forwarder) DeviceTraffic() []DeviceTrafficStats {
	f.trafficMu.RLock()
	result := make([]DeviceTrafficStats, 0, len(f.traffic))
	for _, stats := range f.traffic {
		result = append(result, stats)
	}
	f.trafficMu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].MAC < result[j].MAC })
	return result
}

func (f *Forwarder) classify(frame []byte) (queuedFrame, error) {
	if len(frame) < ethernetHeaderLength {
		return queuedFrame{}, ErrFrameNotManaged
	}
	_, destinationIP, networkLength, ok := classifyNetworkPacket(frame)
	if !ok {
		return queuedFrame{}, ErrFrameNotManaged
	}
	destination, source := net.HardwareAddr(frame[:6]), net.HardwareAddr(frame[6:12])
	if !bytes.Equal(destination, f.localMAC) {
		return queuedFrame{}, ErrFrameNotManaged
	}
	var gatewayMAC [6]byte
	f.identityMu.RLock()
	gatewayLength := copy(gatewayMAC[:], f.gatewayMAC)
	f.identityMu.RUnlock()
	if gatewayLength != len(gatewayMAC) {
		return queuedFrame{}, ErrFrameNotManaged
	}
	result := queuedFrame{data: append([]byte(nil), frame[:ethernetHeaderLength+networkLength]...)}
	if bytes.Equal(source, gatewayMAC[:]) {
		f.routesMu.RLock()
		route := f.routes[destinationIP]
		f.routesMu.RUnlock()
		if !f.manager.hasKey(route.key) {
			return queuedFrame{}, ErrFrameNotManaged
		}
		result.deviceMAC, result.deviceKey, result.direction = route.mac, route.key, Download
		result.limited = f.manager.limitedKey(route.key)
		copy(result.data[:6], route.mac)
		copy(result.data[6:12], f.localMAC)
		return result, nil
	}
	deviceKey, err := normalizeDeviceMAC(source)
	if err != nil || !f.manager.hasKey(deviceKey) {
		return queuedFrame{}, ErrFrameNotManaged
	}
	result.deviceMAC, result.deviceKey, result.direction = append(net.HardwareAddr(nil), source...), deviceKey, Upload
	result.limited = f.manager.limitedKey(deviceKey)
	copy(result.data[:6], gatewayMAC[:])
	copy(result.data[6:12], f.localMAC)
	return result, nil
}

func (f *Forwarder) recordQueueDrop(frame queuedFrame) {
	f.queueDrops.Add(1)
	if frame.direction == Download {
		f.downloadQueueDrops.Add(1)
	} else {
		f.uploadQueueDrops.Add(1)
	}
	if frame.limited {
		f.limitedQueueDrops.Add(1)
	} else {
		f.monitorQueueDrops.Add(1)
	}
	key := frame.deviceKey
	if key == "" {
		var err error
		key, err = normalizeDeviceMAC(frame.deviceMAC)
		if err != nil {
			return
		}
	}
	f.dropMu.Lock()
	drops := f.deviceDrops[key]
	drops.MAC = key
	if frame.direction == Download {
		drops.DownloadDrops++
	} else {
		drops.UploadDrops++
	}
	f.deviceDrops[key] = drops
	f.dropMu.Unlock()
}

func updatePeak(peak *atomic.Uint64, depth int) {
	candidate := uint64(depth)
	for current := peak.Load(); candidate > current; current = peak.Load() {
		if peak.CompareAndSwap(current, candidate) {
			return
		}
	}
}

func classifyNetworkPacket(frame []byte) (netip.Addr, netip.Addr, int, bool) {
	if len(frame) < ethernetHeaderLength {
		return netip.Addr{}, netip.Addr{}, 0, false
	}
	network := frame[ethernetHeaderLength:]
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case etherTypeIPv4:
		if len(network) < 20 {
			return netip.Addr{}, netip.Addr{}, 0, false
		}
		headerLength := int(network[0]&0x0f) * 4
		totalLength := int(binary.BigEndian.Uint16(network[2:4]))
		if network[0]>>4 != 4 || headerLength < 20 || totalLength < headerLength || totalLength > len(network) {
			return netip.Addr{}, netip.Addr{}, 0, false
		}
		return netip.AddrFrom4([4]byte(network[12:16])), netip.AddrFrom4([4]byte(network[16:20])), totalLength, true
	case etherTypeIPv6:
		if len(network) < 40 || network[0]>>4 != 6 {
			return netip.Addr{}, netip.Addr{}, 0, false
		}
		payloadLength := int(binary.BigEndian.Uint16(network[4:6]))
		totalLength := 40 + payloadLength
		if payloadLength == 0 {
			totalLength = len(network)
		}
		if totalLength > len(network) {
			return netip.Addr{}, netip.Addr{}, 0, false
		}
		return netip.AddrFrom16([16]byte(network[8:24])), netip.AddrFrom16([16]byte(network[24:40])), totalLength, true
	default:
		return netip.Addr{}, netip.Addr{}, 0, false
	}
}

func (f *Forwarder) recordTraffic(frame queuedFrame) {
	key := frame.deviceKey
	if key == "" {
		var err error
		key, err = normalizeDeviceMAC(frame.deviceMAC)
		if err != nil {
			return
		}
	}
	f.trafficMu.Lock()
	stats := f.traffic[key]
	stats.MAC = key
	if frame.direction == Upload {
		stats.UploadPackets++
		stats.UploadBytes += uint64(len(frame.data))
	} else {
		stats.DownloadPackets++
		stats.DownloadBytes += uint64(len(frame.data))
	}
	f.traffic[key] = stats
	f.trafficMu.Unlock()
}

func (f *Forwarder) drainCanceled(queue *directionalQueue) {
	for {
		select {
		case frame := <-queue.frames:
			queue.release(frame)
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
