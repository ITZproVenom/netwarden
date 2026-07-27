// Package helper implements the narrow protocol used by a privileged capture subprocess.
package helper

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/packet"
)

type Message struct {
	Type       string    `json:"type"`
	Data       []byte    `json:"data,omitempty"`
	CapturedAt time.Time `json:"captured_at,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// Serve exposes only filtered capture and locally sourced ARP requests.
func Serve(ctx context.Context, driver capture.Driver, localMAC net.HardwareAddr, localIP netip.Addr, prefix netip.Prefix, input io.Reader, output io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer driver.Close()
	encoder := json.NewEncoder(output)
	var outputMu sync.Mutex
	write := func(message Message) error {
		outputMu.Lock()
		defer outputMu.Unlock()
		return encoder.Encode(message)
	}
	if err := write(Message{Type: "ready"}); err != nil {
		return err
	}
	runResult := make(chan error, 1)
	go func() {
		runResult <- driver.Run(ctx, func(frame capture.Frame) error {
			return write(Message{Type: "frame", Data: frame.Data, CapturedAt: frame.CapturedAt})
		})
	}()
	decoder := json.NewDecoder(input)
	for {
		var command Message
		if err := decoder.Decode(&command); err != nil {
			if errors.Is(err, io.EOF) {
				cancel()
				return normalizeRunError(<-runResult)
			}
			return err
		}
		switch command.Type {
		case "send":
			if err := ValidateDiscoveryFrame(command.Data, localMAC, localIP, prefix); err != nil {
				_ = write(Message{Type: "error", Error: err.Error()})
				continue
			}
			if err := driver.Send(ctx, command.Data); err != nil {
				_ = write(Message{Type: "error", Error: err.Error()})
			}
		case "close":
			cancel()
			return normalizeRunError(<-runResult)
		default:
			_ = write(Message{Type: "error", Error: "unsupported helper command"})
		}
	}
}

func normalizeRunError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

func ValidateDiscoveryFrame(frame []byte, localMAC net.HardwareAddr, localIP netip.Addr, prefix netip.Prefix) error {
	message, err := packet.ParseARP(frame)
	if err != nil {
		return errors.New("helper accepts only Ethernet/IPv4 ARP frames")
	}
	if message.Operation != packet.ARPOpRequest {
		return errors.New("helper accepts only ARP discovery requests")
	}
	if !bytes.Equal(frame[0:6], []byte{255, 255, 255, 255, 255, 255}) || !bytes.Equal(message.TargetMAC, []byte{0, 0, 0, 0, 0, 0}) {
		return errors.New("ARP discovery must use broadcast Ethernet and an empty target MAC")
	}
	if len(frame) < packet.EthernetHeaderLen || !bytes.Equal(frame[6:12], localMAC) || !bytes.Equal(message.SenderMAC, localMAC) {
		return errors.New("ARP sender MAC does not match the selected interface")
	}
	if message.SenderIP != localIP {
		return errors.New("ARP sender IP does not match the selected interface")
	}
	if !prefix.Masked().Contains(message.TargetIP) || message.TargetIP == localIP {
		return errors.New("ARP target is outside the selected local network")
	}
	masked := prefix.Masked()
	if message.TargetIP == masked.Addr() || prefix.Bits() < 31 && message.TargetIP == ipv4Broadcast(masked) {
		return errors.New("ARP target cannot be the network or broadcast address")
	}
	return nil
}

func ipv4Broadcast(prefix netip.Prefix) netip.Addr {
	address := prefix.Addr().As4()
	value := binary.BigEndian.Uint32(address[:]) | ^uint32(0)>>prefix.Bits()
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], value)
	return netip.AddrFrom4(result)
}
