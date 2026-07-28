// Package helperclient implements capture.Driver through a helper subprocess.
package helperclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/capture/helper"
)

type Driver struct {
	command *exec.Cmd
	input   io.WriteCloser
	frames  chan capture.Frame
	errors  chan error
	mu      sync.Mutex
	closed  bool
}

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
	command := exec.Command(executable, arguments...)
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
	decoder := json.NewDecoder(bufio.NewReader(output))
	var ready helper.Message
	if err := decoder.Decode(&ready); err != nil || ready.Type != "ready" {
		_ = command.Process.Kill()
		if err == nil {
			err = errors.New("helper did not become ready")
		}
		return nil, fmt.Errorf("start capture helper: %w", err)
	}
	driver := &Driver{command: command, input: input, frames: make(chan capture.Frame, 64), errors: make(chan error, 1)}
	go driver.read(decoder)
	return driver, nil
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
			d.report(err)
			return
		}
		switch message.Type {
		case "frame":
			d.frames <- capture.Frame{Data: message.Data, CapturedAt: message.CapturedAt}
		case "error":
			d.report(errors.New(message.Error))
		}
	}
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
	_ = json.NewEncoder(d.input).Encode(helper.Message{Type: "close"})
	_ = d.input.Close()
	d.mu.Unlock()
	return d.command.Wait()
}

func (d *Driver) report(err error) {
	select {
	case d.errors <- err:
	default:
	}
}
