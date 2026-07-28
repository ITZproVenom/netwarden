package core

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/packet"
)

type memoryDriver struct {
	frames chan capture.Frame
	once   sync.Once
}

type staticEnricher struct{}

func (staticEnricher) Enrich(device.Device) device.Metadata {
	return device.Metadata{Name: "Router", Vendor: "Test Vendor"}
}

func (d *memoryDriver) Run(ctx context.Context, consume func(capture.Frame) error) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case frame := <-d.frames:
			if err := consume(frame); err != nil {
				return err
			}
		}
	}
}

func (d *memoryDriver) Send(context.Context, []byte) error { return nil }
func (d *memoryDriver) Close() error                       { return nil }

func TestServiceObservesARPFramesAndStops(t *testing.T) {
	driver := &memoryDriver{frames: make(chan capture.Frame, 1)}
	registry := device.NewRegistry()
	service := NewService(driver, registry, time.Minute, time.Second, WithEnricher(staticEnricher{}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()

	sender, _ := net.ParseMAC("02:00:00:00:00:10")
	target, _ := net.ParseMAC("02:00:00:00:00:01")
	frame, err := packet.MarshalARP(target, sender, packet.ARP{
		Operation: packet.ARPOpReply,
		SenderMAC: sender,
		SenderIP:  netip.MustParseAddr("192.168.1.10"),
		TargetMAC: target,
		TargetIP:  netip.MustParseAddr("192.168.1.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	driver.frames <- capture.Frame{Data: frame}

	select {
	case event := <-service.Events():
		if event.Kind != EventObserved || event.Device.IP.String() != "192.168.1.10" ||
			event.Device.Name != "Router" || event.Device.Vendor != "Test Vendor" {
			t.Fatalf("unexpected event: %#v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for observation")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("service did not stop after cancellation")
	}
}

func TestServiceAccountsForDroppedEvents(t *testing.T) {
	service := NewService(&memoryDriver{}, device.NewRegistry(), time.Minute, time.Second)
	for i := 0; i < cap(service.events)+3; i++ {
		service.publish(Event{Kind: EventDiscovered})
	}
	if got := service.DroppedEvents(); got != 3 {
		t.Fatalf("got %d dropped events, want 3", got)
	}
}

func TestServiceIgnoresLocallySourcedFrames(t *testing.T) {
	localMAC, _ := net.ParseMAC("02:00:00:00:00:10")
	targetMAC, _ := net.ParseMAC("02:00:00:00:00:20")
	registry := device.NewRegistry()
	service := NewService(&memoryDriver{}, registry, time.Minute, time.Second, WithIgnoredSenderMAC(localMAC))
	frame, err := packet.MarshalARP(targetMAC, localMAC, packet.ARP{
		Operation: packet.ARPOpReply, SenderMAC: localMAC, SenderIP: netip.MustParseAddr("192.168.1.1"),
		TargetMAC: targetMAC, TargetIP: netip.MustParseAddr("192.168.1.20"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.handleFrame(capture.Frame{Data: frame}); err != nil {
		t.Fatal(err)
	}
	if devices := registry.Snapshot(); len(devices) != 0 {
		t.Fatalf("locally sourced frame created %d devices", len(devices))
	}
}
