package shaping

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// benchmarkSender deliberately does not copy frames. The forwarder owns the
// submitted frame copy until Send returns, so this models a synchronous driver
// call while keeping driver-specific syscall costs out of the core benchmark.
type benchmarkSender struct {
	forwarded atomic.Uint64
}

func (s *benchmarkSender) Send(context.Context, []byte) error {
	s.forwarded.Add(1)
	return nil
}

type benchmarkRoute struct {
	mac net.HardwareAddr
	ip  netip.Addr
}

// BenchmarkForwarderEndToEnd measures the portable forwarding core from
// Submit through classification, frame copying, bounded admission, scheduling,
// Ethernet rewriting, accounting, and sender dispatch. It intentionally does
// not claim to measure pcap/Npcap capture, helper IPC, or packet injection.
//
// Run a stable sample with:
//
//	go test -run '^$' -bench '^BenchmarkForwarderEndToEnd$' -benchmem -benchtime=3s -count=5 ./internal/shaping
func BenchmarkForwarderEndToEnd(b *testing.B) {
	for _, frameBytes := range []int{64, 512, 1514} {
		frameBytes := frameBytes
		b.Run(fmt.Sprintf("IPv4/Monitor/Upload/%dB", frameBytes), func(b *testing.B) {
			benchmarkForwarder(b, frameBytes, 1, false, false, false)
		})
		b.Run(fmt.Sprintf("IPv4/Monitor/Bidirectional/%dB", frameBytes), func(b *testing.B) {
			benchmarkForwarder(b, frameBytes, 1, false, true, false)
		})
		b.Run(fmt.Sprintf("IPv4/Monitor/16Devices/%dB", frameBytes), func(b *testing.B) {
			benchmarkForwarder(b, frameBytes, 16, false, true, false)
		})
		b.Run(fmt.Sprintf("IPv4/LimitedScheduler/16Devices/%dB", frameBytes), func(b *testing.B) {
			benchmarkForwarder(b, frameBytes, 16, true, true, false)
		})
		b.Run(fmt.Sprintf("IPv6/Monitor/16Devices/%dB", frameBytes), func(b *testing.B) {
			benchmarkForwarder(b, frameBytes, 16, false, true, true)
		})
	}
}

func benchmarkForwarder(b *testing.B, frameBytes, deviceCount int, limited, bidirectional, ipv6 bool) {
	b.Helper()
	if frameBytes < ethernetHeaderLength+40 && ipv6 {
		b.Fatalf("IPv6 benchmark frame is too small: %d", frameBytes)
	}
	if frameBytes < ethernetHeaderLength+20 && !ipv6 {
		b.Fatalf("IPv4 benchmark frame is too small: %d", frameBytes)
	}

	local := benchmarkMAC(1)
	gateway := benchmarkMAC(2)
	manager := NewManager()
	sender := &benchmarkSender{}
	forwarder, err := NewForwarder(manager, sender, ForwarderConfig{
		LocalMAC:      local,
		GatewayMAC:    gateway,
		QueueCapacity: maximumQueueCapacity,
		QueueBytes:    maximumQueueBytes,
	})
	if err != nil {
		b.Fatal(err)
	}

	routes := make([]benchmarkRoute, deviceCount)
	frames := make([][2][]byte, deviceCount)
	remoteIPv4 := netip.MustParseAddr("198.51.100.1")
	remoteIPv6 := netip.MustParseAddr("2001:db8:ffff::1")
	for i := range deviceCount {
		route := benchmarkRoute{mac: benchmarkMAC(byte(32 + i))}
		if ipv6 {
			route.ip = netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", i+1))
		} else {
			route.ip = netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
		}
		if err := forwarder.SetRoute(route.ip, route.mac); err != nil {
			b.Fatal(err)
		}
		if limited {
			// A very high rate and maximum burst exercise limiter reservations and
			// limited-flow scheduling without turning this into a wall-clock rate test.
			err = manager.Set(route.mac, Policy{
				DownloadBitsPerSecond: 1_000_000_000_000,
				UploadBitsPerSecond:   1_000_000_000_000,
				BurstBytes:            MaximumBurstBytes,
			})
		} else {
			err = manager.Track(route.mac)
		}
		if err != nil {
			b.Fatal(err)
		}
		if ipv6 {
			frames[i][0] = ipv6Frame(local, route.mac, route.ip, remoteIPv6, frameBytes-ethernetHeaderLength-40)
			frames[i][1] = ipv6Frame(local, gateway, remoteIPv6, route.ip, frameBytes-ethernetHeaderLength-40)
		} else {
			frames[i][0] = ipv4Frame(local, route.mac, route.ip, remoteIPv4, frameBytes-ethernetHeaderLength-20)
			frames[i][1] = ipv4Frame(local, gateway, remoteIPv4, route.ip, frameBytes-ethernetHeaderLength-20)
		}
		routes[i] = route
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- forwarder.Run(ctx) }()

	b.ReportAllocs()
	b.SetBytes(int64(frameBytes))
	b.ResetTimer()
	started := time.Now()
	for i := 0; i < b.N; i++ {
		// Keep admission below saturation so the benchmark measures successful
		// forwarding rather than repeated allocation-and-drop attempts.
		for forwarder.upload.count.Load()+forwarder.download.count.Load() >= maximumQueueCapacity/2 {
			runtime.Gosched()
		}
		deviceIndex := i % deviceCount
		directionIndex := 0
		if bidirectional {
			directionIndex = (i / deviceCount) & 1
		}
		if err := forwarder.Submit(frames[deviceIndex][directionIndex]); err != nil {
			b.Fatalf("submit frame %d: %v", i, err)
		}
	}
	for sender.forwarded.Load() != uint64(b.N) {
		runtime.Gosched()
	}
	elapsed := time.Since(started)
	b.StopTimer()
	b.ReportMetric(float64(b.N)/elapsed.Seconds(), "packets/s")

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		b.Fatalf("stop forwarder: %v", err)
	}
	stats := forwarder.Stats()
	if stats.Accepted != uint64(b.N) || stats.Forwarded != uint64(b.N) || stats.QueueDrops != 0 || stats.SendErrors != 0 {
		b.Fatalf("unexpected final stats: %#v", stats)
	}
}

func benchmarkMAC(last byte) net.HardwareAddr {
	return net.HardwareAddr{0x02, 0, 0, 0, 0, last}
}
