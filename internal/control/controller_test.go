package control

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/packet"
)

type recordingSender struct {
	mu     sync.Mutex
	frames [][]byte
	err    error
}

type failFirstSender struct {
	recordingSender
	calls int
}

func (s *failFirstSender) Send(ctx context.Context, frame []byte) error {
	s.calls++
	if err := s.recordingSender.Send(ctx, frame); err != nil {
		return err
	}
	if s.calls == 1 {
		return errors.New("ambiguous adapter failure")
	}
	return nil
}

func (s *recordingSender) Send(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frames = append(s.frames, append([]byte(nil), frame...))
	return s.err
}

func (s *recordingSender) messages(t *testing.T) []packet.ARP {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	messages := make([]packet.ARP, 0, len(s.frames))
	for _, frame := range s.frames {
		message, err := packet.ParseARP(frame)
		if err != nil {
			t.Fatal(err)
		}
		messages = append(messages, message)
	}
	return messages
}

func TestRestoreRemovesStateAndSendsCorrections(t *testing.T) {
	sender := &recordingSender{}
	controller := testController(t, sender)
	target := endpoint(t, "192.168.1.20", "02:00:00:00:00:20")
	if err := controller.Isolate(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if len(controller.Snapshot()) != 1 {
		t.Fatal("target was not recorded")
	}
	if err := controller.Restore(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if len(controller.Snapshot()) != 0 {
		t.Fatal("target remained isolated")
	}
	messages := sender.messages(t)
	if len(messages) != 4 {
		t.Fatalf("got %d messages, want one isolation and three corrections", len(messages))
	}
	for _, message := range messages[1:] {
		if message.SenderMAC.String() != testGateway(t).MAC.String() {
			t.Fatalf("correction used %s instead of gateway", message.SenderMAC)
		}
	}
}

func TestCancellationRestoresEveryTarget(t *testing.T) {
	sender := &recordingSender{}
	controller := testController(t, sender)
	target := endpoint(t, "192.168.1.20", "02:00:00:00:00:20")
	if err := controller.Isolate(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- controller.Run(ctx) }()
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	if len(controller.Snapshot()) != 0 {
		t.Fatal("shutdown retained isolation state")
	}
	if got := len(sender.messages(t)); got != 4 {
		t.Fatalf("got %d messages, want one isolation and three shutdown corrections", got)
	}
}

func TestAmbiguousIsolationFailureTriggersCorrection(t *testing.T) {
	sender := &failFirstSender{}
	controller := testController(t, sender)
	target := endpoint(t, "192.168.1.20", "02:00:00:00:00:20")
	if err := controller.Isolate(context.Background(), target); err == nil {
		t.Fatal("expected isolation failure")
	}
	if len(controller.Snapshot()) != 0 {
		t.Fatal("failed target remained in desired state")
	}
	messages := sender.messages(t)
	if len(messages) != 4 {
		t.Fatalf("got %d messages, want failed attempt plus three corrections", len(messages))
	}
	for _, message := range messages[1:] {
		if message.SenderMAC.String() != testGateway(t).MAC.String() {
			t.Fatalf("failure correction used %s instead of gateway", message.SenderMAC)
		}
	}
}

func TestControllerRejectsGatewayAndOffSubnetTargets(t *testing.T) {
	controller := testController(t, &recordingSender{})
	for _, target := range []Endpoint{
		testGateway(t),
		endpoint(t, "10.0.0.2", "02:00:00:00:00:22"),
		endpoint(t, "192.168.1.255", "02:00:00:00:00:23"),
	} {
		if err := controller.Isolate(context.Background(), target); !errors.Is(err, ErrInvalidTarget) {
			t.Fatalf("target %#v: got %v, want ErrInvalidTarget", target, err)
		}
	}
}

func testController(t *testing.T, sender Sender) *Controller {
	t.Helper()
	controller, err := NewController(sender, testLocal(t), testGateway(t), netip.MustParsePrefix("192.168.1.0/24"), Options{
		RefreshInterval:  time.Hour,
		RestorationCount: 3,
		RestorationDelay: time.Nanosecond,
		ShutdownTimeout:  time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func testLocal(t *testing.T) Endpoint {
	return endpoint(t, "192.168.1.10", "02:00:00:00:00:10")
}

func testGateway(t *testing.T) Endpoint {
	return endpoint(t, "192.168.1.1", "00:00:0c:00:00:01")
}
