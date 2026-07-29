package helperclient

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/capture/helper"
)

func TestOpenConnectionUsesExistingTransport(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	command := make(chan helper.Message, 1)
	go func() {
		encoder := json.NewEncoder(server)
		decoder := json.NewDecoder(server)
		if err := encoder.Encode(helper.Message{Type: "ready"}); err != nil {
			return
		}
		var message helper.Message
		if err := decoder.Decode(&message); err == nil {
			command <- message
		}
	}()

	driver, err := OpenConnection(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-command:
		if message.Type != "close" {
			t.Fatalf("close message type = %q", message.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("helper did not receive close message")
	}
}

func TestOpenConnectionStopsWaitingWhenContextIsCanceled(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	started := time.Now()
	if _, err := OpenConnection(ctx, client); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context cancellation", err)
	}
	if time.Since(started) > time.Second {
		t.Fatal("canceled helper startup did not return promptly")
	}
}

func TestCloseUnblocksSaturatedFrameReader(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	commands := make(chan helper.Message, 1)
	go func() {
		var message helper.Message
		if err := json.NewDecoder(server).Decode(&message); err == nil {
			commands <- message
		}
	}()
	encoder := json.NewEncoder(server)
	framesDone := make(chan struct{})
	go func() {
		defer close(framesDone)
		if encoder.Encode(helper.Message{Type: "ready"}) != nil {
			return
		}
		for index := 0; index < 256; index++ {
			if encoder.Encode(helper.Message{Type: "frame", Data: []byte{byte(index)}}) != nil {
				return
			}
		}
	}()
	driver, err := OpenConnection(context.Background(), client)
	if err != nil {
		t.Fatal(err)
	}

	closed := make(chan error, 1)
	go func() { closed <- driver.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("driver close blocked behind saturated frame delivery")
	}
	select {
	case message := <-commands:
		if message.Type != "close" {
			t.Fatalf("close message type = %q", message.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("helper did not receive close message")
	}
	<-framesDone
}
