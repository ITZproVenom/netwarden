package helperclient

import (
	"context"
	"encoding/json"
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
