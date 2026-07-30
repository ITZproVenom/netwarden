// Package helperclient implements capture.Driver through a helper subprocess.
package helperclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/capture/helper"
	"github.com/amdzy/NetWarden/internal/shaping"
)

type Driver struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  io.Closer
	wait    <-chan error
	done    chan struct{}
	frames  chan capture.Frame
	errors  chan error
	mu      sync.Mutex
	closed  bool
	stop    sync.Once
	pending map[string]chan helperResponse
	nextID  atomic.Uint64
}

type helperResponse struct {
	message helper.Message
	err     error
}

const (
	helperReadyTimeout    = 45 * time.Second
	helperShutdownTimeout = 5 * time.Second
)

func Open(ctx context.Context, executable string, arguments ...string) (*Driver, error) {
	return OpenWithEnv(ctx, executable, nil, arguments...)
}

// OpenWithEnv starts a helper with narrowly scoped environment overrides. It
// is used by GUI elevation mechanisms such as sudo askpass without changing
// the capture protocol or inheriting duplicate values for the same key.
func OpenWithEnv(ctx context.Context, executable string, environment map[string]string, arguments ...string) (*Driver, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = mergeEnvironment(os.Environ(), environment)
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	decoder := json.NewDecoder(bufio.NewReader(output))
	ready, err := waitUntilReady(ctx, decoder)
	if err != nil || ready.Type != "ready" {
		_ = command.Process.Kill()
		_ = output.Close()
		<-wait
		if err == nil {
			err = errors.New("helper did not become ready")
		}
		return nil, fmt.Errorf("start capture helper: %w", err)
	}
	driver := newDriver(input, output, wait)
	driver.command = command
	go driver.read(decoder)
	return driver, nil
}

// OpenConnection attaches the capture protocol to an already authenticated
// full-duplex connection. Platform launchers use this when an elevation API
// cannot preserve a child process's standard input and output handles.
func OpenConnection(ctx context.Context, connection io.ReadWriteCloser) (*Driver, error) {
	if err := ctx.Err(); err != nil {
		_ = connection.Close()
		return nil, err
	}
	decoder := json.NewDecoder(bufio.NewReader(connection))
	ready, err := waitUntilReady(ctx, decoder)
	if err != nil || ready.Type != "ready" {
		_ = connection.Close()
		if err == nil {
			err = errors.New("helper did not become ready")
		}
		return nil, fmt.Errorf("start capture helper: %w", err)
	}
	driver := newDriver(connection, connection, nil)
	go driver.read(decoder)
	return driver, nil
}

func newDriver(input io.WriteCloser, output io.Closer, wait <-chan error) *Driver {
	return &Driver{input: input, output: output, wait: wait, done: make(chan struct{}), frames: make(chan capture.Frame, 64), errors: make(chan error, 1), pending: make(map[string]chan helperResponse)}
}

func waitUntilReady(ctx context.Context, decoder *json.Decoder) (helper.Message, error) {
	type result struct {
		message helper.Message
		err     error
	}
	ready := make(chan result, 1)
	go func() {
		var message helper.Message
		err := decoder.Decode(&message)
		ready <- result{message: message, err: err}
	}()
	timer := time.NewTimer(helperReadyTimeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return helper.Message{}, ctx.Err()
	case <-timer.C:
		return helper.Message{}, errors.New("capture helper readiness timed out")
	case result := <-ready:
		return result.message, result.err
	}
}

func mergeEnvironment(base []string, overrides map[string]string) []string {
	result := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		key, _, found := strings.Cut(entry, "=")
		if _, replaced := overrides[key]; found && replaced {
			continue
		}
		result = append(result, entry)
	}
	for key, value := range overrides {
		result = append(result, key+"="+value)
	}
	return result
}

func (d *Driver) read(decoder *json.Decoder) {
	for {
		var message helper.Message
		if err := decoder.Decode(&message); err != nil {
			d.stop.Do(func() { close(d.done) })
			d.report(err)
			return
		}
		switch message.Type {
		case "frame":
			select {
			case d.frames <- capture.Frame{Data: message.Data, CapturedAt: message.CapturedAt}:
			case <-d.done:
				return
			}
		case "error":
			d.report(errors.New(message.Error))
		case "result":
			d.mu.Lock()
			response := d.pending[message.RequestID]
			delete(d.pending, message.RequestID)
			d.mu.Unlock()
			if response != nil {
				var err error
				if message.Error != "" {
					err = errors.New(message.Error)
				}
				response <- helperResponse{message: message, err: err}
			}
		}
	}
}

// SetBandwidthLimit installs a validated policy in the privileged helper.
// Redirected packet payloads never cross into this client process.
func (d *Driver) SetBandwidthLimit(ctx context.Context, ip netip.Addr, mac net.HardwareAddr, policy shaping.Policy) error {
	_, err := d.request(ctx, helper.Message{Type: "shape_set", TargetIP: ip.String(), TargetMAC: mac.String(), Policy: &policy})
	return err
}

func (d *Driver) RemoveBandwidthLimit(ctx context.Context, ip netip.Addr, mac net.HardwareAddr) error {
	_, err := d.request(ctx, helper.Message{Type: "shape_remove", TargetIP: ip.String(), TargetMAC: mac.String()})
	return err
}

func (d *Driver) StartBandwidthMonitor(ctx context.Context, ip netip.Addr, mac net.HardwareAddr) error {
	_, err := d.request(ctx, helper.Message{Type: "monitor_set", TargetIP: ip.String(), TargetMAC: mac.String()})
	return err
}

func (d *Driver) StopBandwidthMonitor(ctx context.Context, ip netip.Addr, mac net.HardwareAddr) error {
	_, err := d.request(ctx, helper.Message{Type: "monitor_remove", TargetIP: ip.String(), TargetMAC: mac.String()})
	return err
}

func (d *Driver) BandwidthTraffic(ctx context.Context) ([]shaping.DeviceTrafficStats, error) {
	response, err := d.request(ctx, helper.Message{Type: "shape_traffic"})
	return response.Traffic, err
}

func (d *Driver) request(ctx context.Context, command helper.Message) (helper.Message, error) {
	if err := ctx.Err(); err != nil {
		return helper.Message{}, err
	}
	command.RequestID = fmt.Sprintf("%d", d.nextID.Add(1))
	response := make(chan helperResponse, 1)
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return helper.Message{}, errors.New("capture helper is closed")
	}
	d.pending[command.RequestID] = response
	if err := json.NewEncoder(d.input).Encode(command); err != nil {
		delete(d.pending, command.RequestID)
		d.mu.Unlock()
		return helper.Message{}, err
	}
	d.mu.Unlock()
	select {
	case result := <-response:
		return result.message, result.err
	case <-ctx.Done():
		d.removePending(command.RequestID)
		return helper.Message{}, ctx.Err()
	case <-d.done:
		d.removePending(command.RequestID)
		return helper.Message{}, errors.New("capture helper stopped before replying")
	}
}

func (d *Driver) removePending(requestID string) {
	d.mu.Lock()
	delete(d.pending, requestID)
	d.mu.Unlock()
}

func (d *Driver) Run(ctx context.Context, consume func(capture.Frame) error) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-d.errors:
			return err
		case frame := <-d.frames:
			if err := consume(frame); err != nil {
				return err
			}
		}
	}
}

func (d *Driver) Send(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("capture helper is closed")
	}
	return json.NewEncoder(d.input).Encode(helper.Message{Type: "send", Data: frame})
}

func (d *Driver) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	d.stop.Do(func() { close(d.done) })
	_ = json.NewEncoder(d.input).Encode(helper.Message{Type: "close"})
	_ = d.input.Close()
	if d.output != nil {
		_ = d.output.Close()
	}
	wait := d.wait
	command := d.command
	d.mu.Unlock()
	if wait != nil {
		timer := time.NewTimer(helperShutdownTimeout)
		defer timer.Stop()
		select {
		case err := <-wait:
			return normalizeWaitError(err)
		case <-timer.C:
			if command != nil && command.Process != nil {
				_ = command.Process.Kill()
			}
			<-wait
			return errors.New("capture helper shutdown timed out")
		}
	}
	return nil
}

func normalizeWaitError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) {
		return nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return nil
	}
	return err
}

func (d *Driver) report(err error) {
	select {
	case d.errors <- err:
	default:
	}
}
