package helper

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/packet"
	"github.com/amdzy/NetWarden/internal/shaping"
)

type bandwidthRecorder struct {
	mu     sync.Mutex
	frames [][]byte
	sent   chan []byte
}

func (r *bandwidthRecorder) send(_ context.Context, frame []byte) error {
	copyOfFrame := append([]byte(nil), frame...)
	r.mu.Lock()
	r.frames = append(r.frames, copyOfFrame)
	r.mu.Unlock()
	select {
	case r.sent <- copyOfFrame:
	default:
	}
	return nil
}

func TestBandwidthSessionRedirectsForwardsAndRestores(t *testing.T) {
	local := mustHelperMAC(t, "02:00:00:00:00:10")
	gateway := mustHelperMAC(t, "02:00:00:00:00:01")
	device := mustHelperMAC(t, "02:00:00:00:00:20")
	localIP := netip.MustParseAddr("192.168.1.10")
	gatewayIP := netip.MustParseAddr("192.168.1.1")
	deviceIP := netip.MustParseAddr("192.168.1.20")
	recorder := &bandwidthRecorder{sent: make(chan []byte, 16)}
	session, err := newBandwidthSession(context.Background(), local, localIP, gatewayIP, netip.MustParsePrefix("192.168.1.10/24"), recorder.send)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.close() })
	policy := shaping.Policy{DownloadBitsPerSecond: 100_000_000, UploadBitsPerSecond: 100_000_000}
	if err := session.set(context.Background(), deviceIP, device, policy); err == nil {
		t.Fatal("policy activated before the gateway identity was verified")
	}
	session.observeGateway(gateway)
	if err := session.set(context.Background(), deviceIP, device, policy); err != nil {
		t.Fatal(err)
	}
	redirectDevice := receiveBandwidthFrame(t, recorder.sent)
	redirectGateway := receiveBandwidthFrame(t, recorder.sent)
	assertARPIdentity(t, redirectDevice, gatewayIP, local, deviceIP, device)
	assertARPIdentity(t, redirectGateway, deviceIP, local, gatewayIP, gateway)

	upload := helperIPv4Frame(local, device, deviceIP, netip.MustParseAddr("1.1.1.1"))
	if !session.submit(upload) {
		t.Fatal("managed upload was not accepted")
	}
	forwarded := receiveBandwidthFrame(t, recorder.sent)
	if string(forwarded[:6]) != string(gateway) || string(forwarded[6:12]) != string(local) {
		t.Fatalf("forwarded Ethernet identities = %x", forwarded[:12])
	}

	if err := session.remove(context.Background(), deviceIP, device); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		toDevice := receiveBandwidthFrame(t, recorder.sent)
		toGateway := receiveBandwidthFrame(t, recorder.sent)
		assertARPIdentity(t, toDevice, gatewayIP, gateway, deviceIP, device)
		assertARPIdentity(t, toGateway, deviceIP, device, gatewayIP, gateway)
	}
}

func TestBandwidthSessionRejectsUnsafeTargets(t *testing.T) {
	local := mustHelperMAC(t, "02:00:00:00:00:10")
	gateway := mustHelperMAC(t, "02:00:00:00:00:01")
	recorder := &bandwidthRecorder{sent: make(chan []byte, 4)}
	session, err := newBandwidthSession(context.Background(), local, netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("192.168.1.1"), netip.MustParsePrefix("192.168.1.10/24"), recorder.send)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.close() })
	session.observeGateway(gateway)
	policy := shaping.Policy{UploadBitsPerSecond: 1_000_000}
	for _, test := range []struct {
		ip  string
		mac net.HardwareAddr
	}{
		{"10.0.0.2", mustHelperMAC(t, "02:00:00:00:00:20")},
		{"192.168.1.1", mustHelperMAC(t, "02:00:00:00:00:20")},
		{"192.168.1.20", gateway},
		{"192.168.1.20", net.HardwareAddr{1, 0, 0, 0, 0, 1}},
	} {
		if err := session.set(context.Background(), netip.MustParseAddr(test.ip), test.mac, policy); err == nil {
			t.Fatalf("unsafe target %s/%s was accepted", test.ip, test.mac)
		}
	}
}

func TestBandwidthSessionDoesNotConsumeUnmanagedIPv6Discovery(t *testing.T) {
	local := mustHelperMAC(t, "02:00:00:00:00:10")
	device := mustHelperMAC(t, "02:00:00:00:00:20")
	recorder := &bandwidthRecorder{sent: make(chan []byte, 1)}
	session, err := newBandwidthSession(context.Background(), local, netip.MustParseAddr("192.168.1.10"),
		netip.MustParseAddr("192.168.1.1"), netip.MustParsePrefix("192.168.1.10/24"), recorder.send)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.close() })
	frame := make([]byte, packet.EthernetHeaderLen+40)
	copy(frame[:6], []byte{0x33, 0x33, 0, 0, 0, 1})
	copy(frame[6:12], device)
	binary.BigEndian.PutUint16(frame[12:14], packet.EtherTypeIPv6)
	frame[14] = 0x60
	if !isIPFrame(frame) || session.submit(frame) {
		t.Fatal("unmanaged IPv6 frame was not left for discovery")
	}
}

func TestBandwidthSessionRedirectsAndRestoresEveryDualStackRoute(t *testing.T) {
	local := mustHelperMAC(t, "02:00:00:00:00:10")
	gateway := mustHelperMAC(t, "02:00:00:00:00:01")
	device := mustHelperMAC(t, "02:00:00:00:00:20")
	local6, router6, device6 := netip.MustParseAddr("fe80::10"), netip.MustParseAddr("fe80::1"), netip.MustParseAddr("2001:db8:1::20")
	device4 := netip.MustParseAddr("192.168.1.20")
	recorder := &bandwidthRecorder{sent: make(chan []byte, 32)}
	session, err := newBandwidthSession(context.Background(), local, netip.MustParseAddr("192.168.1.10"), netip.MustParseAddr("192.168.1.1"), netip.MustParsePrefix("192.168.1.10/24"), recorder.send)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.close() })
	session.observeGateway(gateway)
	session.observeNDP(packet.NDP{Type: packet.ICMPv6NeighborSolicitation, SourceIP: local6, SourceMAC: local})
	session.observeNDP(packet.NDP{Type: packet.ICMPv6RouterAdvertisement, SourceIP: router6, SourceMAC: gateway})
	if err := session.setRoutes(context.Background(), []netip.Addr{device4, device6}, device, shaping.Policy{UploadBitsPerSecond: 1_000_000}); err != nil {
		t.Fatal(err)
	}
	receiveBandwidthFrame(t, recorder.sent)
	receiveBandwidthFrame(t, recorder.sent)
	for range 2 {
		frame := receiveBandwidthFrame(t, recorder.sent)
		message, err := packet.ParseNDP(frame)
		if err != nil || message.Type != packet.ICMPv6NeighborAdvertisement {
			t.Fatalf("IPv6 redirect = %#v, %v", message, err)
		}
	}
	if err := session.removeRoutes(context.Background(), []netip.Addr{device4, device6}, device); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		receiveBandwidthFrame(t, recorder.sent)
	}
	for range 4 {
		frame := receiveBandwidthFrame(t, recorder.sent)
		if _, err := packet.ParseNDP(frame); err != nil {
			t.Fatalf("IPv6 restoration: %v", err)
		}
	}
}

func TestBandwidthSessionTransitionsMonitorLimitAndBackWithoutRestoringEarly(t *testing.T) {
	local := mustHelperMAC(t, "02:00:00:00:00:10")
	gateway := mustHelperMAC(t, "02:00:00:00:00:01")
	device := mustHelperMAC(t, "02:00:00:00:00:20")
	deviceIP := netip.MustParseAddr("192.168.1.20")
	recorder := &bandwidthRecorder{sent: make(chan []byte, 16)}
	session, err := newBandwidthSession(context.Background(), local, netip.MustParseAddr("192.168.1.10"),
		netip.MustParseAddr("192.168.1.1"), netip.MustParsePrefix("192.168.1.10/24"), recorder.send)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.close() })
	session.observeGateway(gateway)
	if err := session.monitor(context.Background(), deviceIP, device); err != nil {
		t.Fatal(err)
	}
	receiveBandwidthFrame(t, recorder.sent)
	receiveBandwidthFrame(t, recorder.sent)
	if err := session.set(context.Background(), deviceIP, device, shaping.Policy{UploadBitsPerSecond: 1_000_000}); err != nil {
		t.Fatal(err)
	}
	receiveBandwidthFrame(t, recorder.sent)
	receiveBandwidthFrame(t, recorder.sent)
	if err := session.monitor(context.Background(), deviceIP, device); err != nil {
		t.Fatal(err)
	}
	select {
	case unexpected := <-recorder.sent:
		t.Fatalf("downgrade unexpectedly restored or redirected the path: %x", unexpected)
	default:
	}
	if err := session.removeMonitor(context.Background(), deviceIP, device); err != nil {
		t.Fatal(err)
	}
	for range 4 {
		receiveBandwidthFrame(t, recorder.sent)
	}
}

func assertARPIdentity(t *testing.T, frame []byte, senderIP netip.Addr, senderMAC net.HardwareAddr, targetIP netip.Addr, targetMAC net.HardwareAddr) {
	t.Helper()
	message, err := packet.ParseARP(frame)
	if err != nil {
		t.Fatal(err)
	}
	if message.SenderIP != senderIP || message.TargetIP != targetIP || string(message.SenderMAC) != string(senderMAC) || string(message.TargetMAC) != string(targetMAC) {
		t.Fatalf("ARP identity = %#v", message)
	}
}

func receiveBandwidthFrame(t *testing.T, frames <-chan []byte) []byte {
	t.Helper()
	select {
	case frame := <-frames:
		return frame
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for helper transmission")
		return nil
	}
}

func mustHelperMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}

func helperIPv4Frame(destinationMAC, sourceMAC net.HardwareAddr, sourceIP, destinationIP netip.Addr) []byte {
	frame := make([]byte, 14+20+16)
	copy(frame[:6], destinationMAC)
	copy(frame[6:12], sourceMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	frame[14] = 0x45
	binary.BigEndian.PutUint16(frame[16:18], uint16(len(frame)-14))
	source := sourceIP.As4()
	destination := destinationIP.As4()
	copy(frame[26:30], source[:])
	copy(frame[30:34], destination[:])
	return frame
}
