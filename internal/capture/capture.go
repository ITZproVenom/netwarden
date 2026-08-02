// Package capture defines the privileged I/O boundary of NetWarden.
package capture

import (
	"context"
	"time"
)

// Frame is copied packet data with the time at which it was observed.
type Frame struct {
	Data       []byte
	CapturedAt time.Time
}

// Driver is implemented by platform adapters backed by libpcap/Npcap or a
// native packet API. Run must return promptly when its context is cancelled.
// The core can be tested with an in-memory implementation.
type Driver interface {
	Run(context.Context, func(Frame) error) error
	Send(context.Context, []byte) error
	Close() error
}

// BorrowedFrameDriver is an optional fast path for synchronous consumers. The
// frame data is valid only until the callback returns and must not be retained.
// Driver.Run remains the ownership-safe default for all other consumers.
type BorrowedFrameDriver interface {
	Driver
	RunBorrowed(context.Context, func(Frame) error) error
}
