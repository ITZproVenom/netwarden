package core

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/device"
	"github.com/gopacket/gopacket/pcapgo"
)

func TestRecordedGatewayReplyFixture(t *testing.T) {
	encoded, err := os.ReadFile("testdata/gateway_reply.pcap.hex")
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(strings.Join(strings.Fields(string(encoded)), ""))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := pcapgo.NewReader(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	packetData, info, err := reader.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(&memoryDriver{}, device.NewRegistry(), time.Minute, time.Second)
	if err := service.handleFrame(capture.Frame{Data: packetData, CapturedAt: info.Timestamp}); err != nil {
		t.Fatal(err)
	}
	event := <-service.Events()
	if event.Kind != EventDiscovered || event.Device.IP.String() != "192.168.1.1" || event.Device.MAC != "00:00:0c:00:00:01" {
		t.Fatalf("unexpected fixture event: %#v", event)
	}
}
