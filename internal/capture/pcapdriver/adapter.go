// Package pcapdriver implements capture.Driver with libpcap on Unix systems
// and Npcap on Windows.
package pcapdriver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/gopacket/gopacket/pcap"
)

const defaultSnapshotLength int32 = 65535

var ErrClosed = errors.New("pcap driver is closed")

type Config struct {
	SnapshotLength int32
	Promiscuous    bool
	ReadTimeout    time.Duration
	Filter         string
}

type Driver struct {
	read  *pcap.Handle
	write *pcap.Handle

	writeMu sync.Mutex
	closeMu sync.Mutex
	closed  bool
}

func Open(device string, config Config) (*Driver, error) {
	if device == "" {
		return nil, errors.New("capture device name is required")
	}
	if config.SnapshotLength <= 0 {
		config.SnapshotLength = defaultSnapshotLength
	}
	if config.ReadTimeout <= 0 {
		config.ReadTimeout = 250 * time.Millisecond
	}

	readHandle, err := pcap.OpenLive(device, config.SnapshotLength, config.Promiscuous, config.ReadTimeout)
	if err != nil {
		return nil, classifyOpenError(device, err)
	}
	if config.Filter != "" {
		if err := readHandle.SetBPFFilter(config.Filter); err != nil {
			readHandle.Close()
			return nil, fmt.Errorf("apply capture filter %q: %w", config.Filter, err)
		}
	}

	writeHandle, err := pcap.OpenLive(device, config.SnapshotLength, config.Promiscuous, config.ReadTimeout)
	if err != nil {
		readHandle.Close()
		return nil, classifyOpenError(device, err)
	}
	return &Driver{read: readHandle, write: writeHandle}, nil
}

func classifyOpenError(device string, err error) error {
	message := strings.ToLower(err.Error())
	kind := capture.ErrRuntimeUnavailable
	switch {
	case os.IsPermission(err), strings.Contains(message, "permission"), strings.Contains(message, "not permitted"), strings.Contains(message, "access is denied"):
		kind = capture.ErrPermissionDenied
	case strings.Contains(message, "no such device"), strings.Contains(message, "not found"), strings.Contains(message, "does not exist"):
		kind = capture.ErrInterfaceMissing
	}
	return capture.NewOperationError(fmt.Sprintf("open capture device %q", device), kind, err)
}

func (d *Driver) Run(ctx context.Context, consume func(capture.Frame) error) error {
	return d.run(ctx, consume, true)
}

// RunBorrowed avoids copying libpcap's buffer for consumers that finish all
// processing before the callback returns.
func (d *Driver) RunBorrowed(ctx context.Context, consume func(capture.Frame) error) error {
	return d.run(ctx, consume, false)
}

func (d *Driver) run(ctx context.Context, consume func(capture.Frame) error, copyFrame bool) error {
	if consume == nil {
		return errors.New("frame consumer is required")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		data, info, err := d.read.ZeroCopyReadPacketData()
		if err != nil {
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read packet: %w", err)
		}
		if copyFrame {
			data = append([]byte(nil), data...)
		}
		frame := capture.Frame{Data: data, CapturedAt: info.Timestamp}
		if err := consume(frame); err != nil {
			return err
		}
	}
}

func (d *Driver) Send(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(frame) == 0 {
		return errors.New("cannot send an empty frame")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if d.closed {
		return ErrClosed
	}
	if err := d.write.WritePacketData(frame); err != nil {
		return fmt.Errorf("send packet: %w", err)
	}
	return nil
}

func (d *Driver) Close() error {
	d.closeMu.Lock()
	defer d.closeMu.Unlock()
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	d.read.Close()
	d.write.Close()
	return nil
}
