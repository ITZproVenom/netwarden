package shaping

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type recordingSender struct {
	mu     sync.Mutex
	frames [][]byte
	err    error
	sent   chan []byte
}

func (s *recordingSender) Send(_ context.Context, frame []byte) error {
	if s.err != nil {
		return s.err
	}
	copyOfFrame := append([]byte(nil), frame...)
	s.mu.Lock()
	s.frames = append(s.frames, copyOfFrame)
	s.mu.Unlock()
	if s.sent != nil {
		s.sent <- copyOfFrame
	}
	return nil
}

func TestForwarderClassifiesRewritesAndForwardsBothDirections(t *testing.T) {
	local := mustMAC(t, "02:00:00:00:00:01")
	gateway := mustMAC(t, "02:00:00:00:00:02")
	device := mustMAC(t, "02:00:00:00:00:20")
	deviceIP := netip.MustParseAddr("192.168.1.20")
	manager := NewManager()
	if err := manager.Set(device, Policy{DownloadBitsPerSecond: 100_000_000, UploadBitsPerSecond: 100_000_000}); err != nil {
		t.Fatal(err)
	}
	sender := &recordingSender{sent: make(chan []byte, 2)}
	forwarder, err := NewForwarder(manager, sender, ForwarderConfig{LocalMAC: local, GatewayMAC: gateway, QueueCapacity: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := forwarder.SetRoute(deviceIP, device); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- forwarder.Run(ctx) }()

	upload := ipv4Frame(local, device, deviceIP, netip.MustParseAddr("1.1.1.1"), 32)
	uploadOriginal := append([]byte(nil), upload...)
	if err := forwarder.Submit(upload); err != nil {
		t.Fatal(err)
	}
	download := ipv4Frame(local, gateway, netip.MustParseAddr("1.1.1.1"), deviceIP, 48)
	if err := forwarder.Submit(download); err != nil {
		t.Fatal(err)
	}

	forwarded := [][]byte{receiveFrame(t, sender.sent), receiveFrame(t, sender.sent)}
	if !bytes.Equal(upload, uploadOriginal) {
		t.Fatal("submit mutated the captured upload frame")
	}
	var gotUpload, gotDownload []byte
	for _, frame := range forwarded {
		if bytes.Equal(frame[:6], gateway) {
			gotUpload = frame
		} else if bytes.Equal(frame[:6], device) {
			gotDownload = frame
		}
	}
	if gotUpload == nil || !bytes.Equal(gotUpload[6:12], local) {
		t.Fatalf("upload Ethernet rewrite = %x", gotUpload)
	}
	if gotDownload == nil || !bytes.Equal(gotDownload[6:12], local) {
		t.Fatalf("download Ethernet rewrite = %x", gotDownload)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("run returned %v", err)
	}
	stats := forwarder.Stats()
	if stats.Accepted != 2 || stats.Forwarded != 2 {
		t.Fatalf("forwarder stats = %#v", stats)
	}
	traffic := forwarder.DeviceTraffic()
	if len(traffic) != 1 || traffic[0].UploadPackets != 1 || traffic[0].DownloadPackets != 1 ||
		traffic[0].UploadBytes != uint64(len(upload)) || traffic[0].DownloadBytes != uint64(len(download)) {
		t.Fatalf("device traffic = %#v", traffic)
	}
}

func TestForwarderClassifiesAndForwardsIPv6BothDirections(t *testing.T) {
	local := mustMAC(t, "02:00:00:00:00:01")
	gateway := mustMAC(t, "02:00:00:00:00:02")
	device := mustMAC(t, "02:00:00:00:00:20")
	deviceIP := netip.MustParseAddr("2001:db8::20")
	manager := NewManager()
	if err := manager.Set(device, Policy{DownloadBitsPerSecond: 100_000_000, UploadBitsPerSecond: 100_000_000}); err != nil {
		t.Fatal(err)
	}
	sender := &recordingSender{sent: make(chan []byte, 2)}
	forwarder, err := NewForwarder(manager, sender, ForwarderConfig{LocalMAC: local, GatewayMAC: gateway, QueueCapacity: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := forwarder.SetRoute(deviceIP, device); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- forwarder.Run(ctx) }()

	upload := ipv6Frame(local, device, deviceIP, netip.MustParseAddr("2001:4860:4860::8888"), 24)
	download := ipv6Frame(local, gateway, netip.MustParseAddr("2001:4860:4860::8888"), deviceIP, 36)
	if err := forwarder.Submit(upload); err != nil {
		t.Fatal(err)
	}
	if err := forwarder.Submit(download); err != nil {
		t.Fatal(err)
	}
	first, second := receiveFrame(t, sender.sent), receiveFrame(t, sender.sent)
	if !(bytes.Equal(first[:6], gateway) || bytes.Equal(second[:6], gateway)) ||
		!(bytes.Equal(first[:6], device) || bytes.Equal(second[:6], device)) {
		t.Fatalf("IPv6 Ethernet rewrites = %x / %x", first[:12], second[:12])
	}
	cancel()
	<-done
	traffic := forwarder.DeviceTraffic()
	if len(traffic) != 1 || traffic[0].UploadBytes != uint64(len(upload)) || traffic[0].DownloadBytes != uint64(len(download)) {
		t.Fatalf("IPv6 device traffic = %#v", traffic)
	}
}

func TestForwarderDropsWhenDirectionalQueueIsFull(t *testing.T) {
	forwarder, manager, local, _, device, deviceIP := testForwarder(t, 1, &recordingSender{})
	if err := manager.Set(device, Policy{UploadBitsPerSecond: 1_000_000}); err != nil {
		t.Fatal(err)
	}
	frame := ipv4Frame(local, device, deviceIP, netip.MustParseAddr("1.1.1.1"), 32)
	if err := forwarder.Submit(frame); err != nil {
		t.Fatal(err)
	}
	if err := forwarder.Submit(frame); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("got %v, want full queue", err)
	}
	stats := forwarder.Stats()
	if stats.QueueDrops != 1 || stats.UploadQueueDrops != 1 || stats.DownloadQueueDrops != 0 ||
		stats.LimitedQueueDrops != 1 || stats.MonitorQueueDrops != 0 || stats.UploadQueueDepth != 1 ||
		stats.PeakUploadDepth != 1 || stats.QueueCapacity != 1 || len(stats.DeviceQueueDrops) != 1 ||
		stats.DeviceQueueDrops[0].MAC != device.String() || stats.DeviceQueueDrops[0].UploadDrops != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestForwarderAttributesMonitoringQueueDrops(t *testing.T) {
	forwarder, manager, local, gateway, device, deviceIP := testForwarder(t, 1, &recordingSender{})
	if err := manager.Track(device); err != nil {
		t.Fatal(err)
	}
	frame := ipv4Frame(local, gateway, netip.MustParseAddr("1.1.1.1"), deviceIP, 32)
	if err := forwarder.Submit(frame); err != nil {
		t.Fatal(err)
	}
	if err := forwarder.Submit(frame); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("got %v, want full queue", err)
	}
	stats := forwarder.Stats()
	if stats.MonitorQueueDrops != 1 || stats.LimitedQueueDrops != 0 || stats.DownloadQueueDrops != 1 ||
		len(stats.DeviceQueueDrops) != 1 || stats.DeviceQueueDrops[0].DownloadDrops != 1 {
		t.Fatalf("stats = %#v", stats)
	}
}

func TestDirectionalQueueEnforcesByteCapacity(t *testing.T) {
	queue := newDirectionalQueue(2, 10)
	first := queuedFrame{data: make([]byte, 6)}
	if !queue.enqueue(first) {
		t.Fatal("first frame was rejected")
	}
	if queue.enqueue(queuedFrame{data: make([]byte, 5)}) {
		t.Fatal("frame exceeding byte capacity was accepted")
	}
	if got := queue.bytes.Load(); got != 6 {
		t.Fatalf("queued bytes = %d, want 6", got)
	}
	queued := <-queue.frames
	queue.release(queued)
	if got := queue.bytes.Load(); got != 0 {
		t.Fatalf("queued bytes after release = %d, want 0", got)
	}
	if got := queue.peakBytes.Load(); got != 6 {
		t.Fatalf("peak queued bytes = %d, want 6", got)
	}
}

func TestForwarderUsesIndependentDirectionalQueues(t *testing.T) {
	forwarder, manager, local, gateway, device, deviceIP := testForwarder(t, 1, &recordingSender{})
	if err := manager.Set(device, Policy{DownloadBitsPerSecond: 1_000_000, UploadBitsPerSecond: 1_000_000}); err != nil {
		t.Fatal(err)
	}
	if err := forwarder.Submit(ipv4Frame(local, device, deviceIP, netip.MustParseAddr("1.1.1.1"), 32)); err != nil {
		t.Fatal(err)
	}
	if err := forwarder.Submit(ipv4Frame(local, gateway, netip.MustParseAddr("1.1.1.1"), deviceIP, 32)); err != nil {
		t.Fatalf("download was blocked by full upload queue: %v", err)
	}
	if forwarder.Stats().Accepted != 2 {
		t.Fatalf("stats = %#v", forwarder.Stats())
	}
}

func TestForwarderReportsSendErrorsAndContinues(t *testing.T) {
	sendErr := errors.New("send failed")
	sender := &recordingSender{err: sendErr}
	forwarder, manager, local, _, device, deviceIP := testForwarder(t, 2, sender)
	if err := manager.Set(device, Policy{UploadBitsPerSecond: 1_000_000}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- forwarder.Run(ctx) }()
	if err := forwarder.Submit(ipv4Frame(local, device, deviceIP, netip.MustParseAddr("1.1.1.1"), 32)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-forwarder.Errors():
		if !errors.Is(err, sendErr) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("send error was not reported")
	}
	cancel()
	<-done
	if forwarder.Stats().SendErrors != 1 {
		t.Fatalf("stats = %#v", forwarder.Stats())
	}
}

func TestForwarderRejectsUnmanagedAndNonIPv4Frames(t *testing.T) {
	forwarder, _, local, _, device, deviceIP := testForwarder(t, 1, &recordingSender{})
	frame := ipv4Frame(local, device, deviceIP, netip.MustParseAddr("1.1.1.1"), 32)
	if err := forwarder.Submit(frame); !errors.Is(err, ErrFrameNotManaged) {
		t.Fatalf("unmanaged frame error = %v", err)
	}
	binary.BigEndian.PutUint16(frame[12:14], 0x86dd)
	if err := forwarder.Submit(frame); !errors.Is(err, ErrFrameNotManaged) {
		t.Fatalf("IPv6 frame error = %v", err)
	}
	if forwarder.Stats().UnmanagedFrames != 2 {
		t.Fatalf("stats = %#v", forwarder.Stats())
	}
}

func TestForwarderDrainsQueuedFramesOnCancellation(t *testing.T) {
	forwarder, manager, local, _, device, deviceIP := testForwarder(t, 2, &recordingSender{})
	if err := manager.Set(device, Policy{UploadBitsPerSecond: 1_000_000}); err != nil {
		t.Fatal(err)
	}
	if err := forwarder.Submit(ipv4Frame(local, device, deviceIP, netip.MustParseAddr("1.1.1.1"), 32)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := forwarder.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if forwarder.Stats().CanceledDrops != 1 {
		t.Fatalf("stats = %#v", forwarder.Stats())
	}
	if err := forwarder.Submit(ipv4Frame(local, device, deviceIP, netip.MustParseAddr("1.1.1.1"), 32)); !errors.Is(err, ErrForwarderStopped) {
		t.Fatalf("submit after stop = %v", err)
	}
}

func testForwarder(t *testing.T, capacity int, sender FrameSender) (*Forwarder, *Manager, net.HardwareAddr, net.HardwareAddr, net.HardwareAddr, netip.Addr) {
	t.Helper()
	local := mustMAC(t, "02:00:00:00:00:01")
	gateway := mustMAC(t, "02:00:00:00:00:02")
	device := mustMAC(t, "02:00:00:00:00:20")
	deviceIP := netip.MustParseAddr("192.168.1.20")
	manager := NewManager()
	forwarder, err := NewForwarder(manager, sender, ForwarderConfig{LocalMAC: local, GatewayMAC: gateway, QueueCapacity: capacity})
	if err != nil {
		t.Fatal(err)
	}
	if err := forwarder.SetRoute(deviceIP, device); err != nil {
		t.Fatal(err)
	}
	return forwarder, manager, local, gateway, device, deviceIP
}

func mustMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}

func ipv4Frame(destinationMAC, sourceMAC net.HardwareAddr, sourceIP, destinationIP netip.Addr, payloadBytes int) []byte {
	frame := make([]byte, ethernetHeaderLength+20+payloadBytes)
	copy(frame[:6], destinationMAC)
	copy(frame[6:12], sourceMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	frame[14] = 0x45
	binary.BigEndian.PutUint16(frame[16:18], uint16(20+payloadBytes))
	source := sourceIP.As4()
	destination := destinationIP.As4()
	copy(frame[26:30], source[:])
	copy(frame[30:34], destination[:])
	return frame
}

func ipv6Frame(destinationMAC, sourceMAC net.HardwareAddr, sourceIP, destinationIP netip.Addr, payloadBytes int) []byte {
	frame := make([]byte, ethernetHeaderLength+40+payloadBytes)
	copy(frame[:6], destinationMAC)
	copy(frame[6:12], sourceMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv6)
	frame[14] = 0x60
	binary.BigEndian.PutUint16(frame[18:20], uint16(payloadBytes))
	source, destination := sourceIP.As16(), destinationIP.As16()
	copy(frame[22:38], source[:])
	copy(frame[38:54], destination[:])
	return frame
}

func receiveFrame(t *testing.T, frames <-chan []byte) []byte {
	t.Helper()
	select {
	case frame := <-frames:
		return frame
	case <-time.After(time.Second):
		t.Fatal("frame was not forwarded")
		return nil
	}
}
