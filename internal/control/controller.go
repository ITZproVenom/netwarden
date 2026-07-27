package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrActiveControlDisabled = errors.New("active device control is not explicitly enabled")
	ErrInvalidTarget         = errors.New("invalid isolation target")
	ErrControllerRunning     = errors.New("control worker is already running")
	ErrControllerStopped     = errors.New("control worker has stopped")
)

type Sender interface {
	Send(context.Context, []byte) error
}

type Options struct {
	// EnableActiveControl must be deliberately set by the application after it
	// has obtained an authorized user action. It is never enabled by default.
	EnableActiveControl bool
	RefreshInterval     time.Duration
	RestorationCount    int
	RestorationDelay    time.Duration
	ShutdownTimeout     time.Duration
}

type State struct {
	Target        Endpoint
	IsolatedSince time.Time
}

type Controller struct {
	sender  Sender
	local   Endpoint
	gateway Endpoint
	prefix  netip.Prefix
	options Options

	operationMu sync.Mutex
	mu          sync.RWMutex
	targets     map[string]State
	running     bool
	stopped     bool
}

func NewController(sender Sender, local, gateway Endpoint, prefix netip.Prefix, options Options) (*Controller, error) {
	if !options.EnableActiveControl {
		return nil, ErrActiveControlDisabled
	}
	if sender == nil {
		return nil, errors.New("packet sender is required")
	}
	if err := validateEndpoint(local); err != nil {
		return nil, fmt.Errorf("local endpoint: %w", err)
	}
	if err := validateEndpoint(gateway); err != nil {
		return nil, fmt.Errorf("gateway endpoint: %w", err)
	}
	if !prefix.IsValid() || !prefix.Addr().Is4() || !prefix.Contains(local.IP) || !prefix.Contains(gateway.IP) {
		return nil, errors.New("local and gateway addresses must be inside the configured IPv4 prefix")
	}
	if local.IP == gateway.IP || equalMAC(local.MAC, gateway.MAC) {
		return nil, errors.New("local and gateway endpoints must be distinct")
	}
	if options.RefreshInterval <= 0 {
		options.RefreshInterval = time.Second
	}
	if options.RestorationCount <= 0 {
		options.RestorationCount = 3
	}
	if options.RestorationDelay <= 0 {
		options.RestorationDelay = 100 * time.Millisecond
	}
	if options.ShutdownTimeout <= 0 {
		options.ShutdownTimeout = 2 * time.Second
	}
	return &Controller{
		sender: sender,
		local:  copyEndpoint(local), gateway: copyEndpoint(gateway),
		prefix: prefix.Masked(), options: options, targets: make(map[string]State),
	}, nil
}

// Isolate records desired state before transmission so every possibly affected
// target remains eligible for corrective restoration if transmission is
// ambiguous or later work fails.
func (c *Controller) Isolate(ctx context.Context, target Endpoint) error {
	if err := c.validateTarget(target); err != nil {
		return err
	}
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	if err := c.ensureUsable(); err != nil {
		return err
	}

	key := canonicalMAC(target.MAC)
	c.mu.Lock()
	state, exists := c.targets[key]
	if !exists {
		state.IsolatedSince = time.Now().UTC()
	}
	state.Target = copyEndpoint(target)
	c.targets[key] = state
	c.mu.Unlock()

	frame, err := isolationFrame(c.local.MAC, c.gateway, target)
	if err == nil {
		err = c.sender.Send(ctx, frame)
	}
	if err == nil {
		return nil
	}

	// A failed send may still have reached the adapter, so restore before
	// forgetting the desired state.
	c.mu.Lock()
	delete(c.targets, key)
	c.mu.Unlock()
	cleanupCtx, cancel := context.WithTimeout(context.Background(), c.options.ShutdownTimeout)
	defer cancel()
	restoreErr := c.restoreTarget(cleanupCtx, target)
	return errors.Join(fmt.Errorf("isolate %s: %w", target.IP, err), restoreErr)
}

// Restore first removes desired isolation state, then sends repeated corrective
// mappings. operationMu ensures a refresh cannot race after restoration.
func (c *Controller) Restore(ctx context.Context, target Endpoint) error {
	if err := c.validateTarget(target); err != nil {
		return err
	}
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	if err := c.ensureUsable(); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.targets, canonicalMAC(target.MAC))
	c.mu.Unlock()
	return c.restoreTarget(ctx, target)
}

func (c *Controller) Snapshot() []State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	states := make([]State, 0, len(c.targets))
	for _, state := range c.targets {
		state.Target = copyEndpoint(state.Target)
		states = append(states, state)
	}
	sort.Slice(states, func(i, j int) bool {
		return canonicalMAC(states[i].Target.MAC) < canonicalMAC(states[j].Target.MAC)
	})
	return states
}

// Run refreshes desired state until cancellation. Cancellation always triggers
// best-effort correction using a fresh, bounded cleanup context.
func (c *Controller) Run(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return ErrControllerRunning
	}
	if c.stopped {
		c.mu.Unlock()
		return ErrControllerStopped
	}
	c.running = true
	c.mu.Unlock()

	ticker := time.NewTicker(c.options.RefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return c.shutdown(ctx.Err())
		case <-ticker.C:
			if err := c.refresh(ctx); err != nil {
				return c.shutdown(err)
			}
		}
	}
}

func (c *Controller) refresh(ctx context.Context) error {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	for _, state := range c.Snapshot() {
		frame, err := isolationFrame(c.local.MAC, c.gateway, state.Target)
		if err != nil {
			return err
		}
		if err := c.sender.Send(ctx, frame); err != nil {
			return fmt.Errorf("refresh isolation for %s: %w", state.Target.IP, err)
		}
	}
	return nil
}

func (c *Controller) shutdown(cause error) error {
	c.operationMu.Lock()
	defer c.operationMu.Unlock()
	c.mu.Lock()
	c.running = false
	c.stopped = true
	states := make([]State, 0, len(c.targets))
	for _, state := range c.targets {
		states = append(states, state)
	}
	clear(c.targets)
	c.mu.Unlock()

	cleanupCtx, cancel := context.WithTimeout(context.Background(), c.options.ShutdownTimeout)
	defer cancel()
	var cleanupErrors []error
	for _, state := range states {
		if err := c.restoreTarget(cleanupCtx, state.Target); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	return errors.Join(append([]error{cause}, cleanupErrors...)...)
}

func (c *Controller) restoreTarget(ctx context.Context, target Endpoint) error {
	frame, err := restorationFrame(c.gateway, target)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < c.options.RestorationCount; attempt++ {
		if err := c.sender.Send(ctx, frame); err != nil {
			return fmt.Errorf("restore %s: %w", target.IP, err)
		}
		if attempt == c.options.RestorationCount-1 || c.options.RestorationDelay == 0 {
			continue
		}
		timer := time.NewTimer(c.options.RestorationDelay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("restore %s: %w", target.IP, ctx.Err())
		case <-timer.C:
		}
	}
	return nil
}

func (c *Controller) validateTarget(target Endpoint) error {
	if err := validateEndpoint(target); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTarget, err)
	}
	if !c.prefix.Contains(target.IP) {
		return fmt.Errorf("%w: address %s is outside %s", ErrInvalidTarget, target.IP, c.prefix)
	}
	if !usableHostAddress(c.prefix, target.IP) {
		return fmt.Errorf("%w: address %s is a network or broadcast address", ErrInvalidTarget, target.IP)
	}
	if target.IP == c.local.IP || target.IP == c.gateway.IP ||
		equalMAC(target.MAC, c.local.MAC) || equalMAC(target.MAC, c.gateway.MAC) {
		return fmt.Errorf("%w: local host and gateway cannot be isolated", ErrInvalidTarget)
	}
	return nil
}

func (c *Controller) ensureUsable() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.stopped {
		return ErrControllerStopped
	}
	return nil
}

func copyEndpoint(endpoint Endpoint) Endpoint {
	return Endpoint{IP: endpoint.IP, MAC: append(net.HardwareAddr(nil), endpoint.MAC...)}
}

func canonicalMAC(mac net.HardwareAddr) string { return strings.ToLower(mac.String()) }

func equalMAC(left, right net.HardwareAddr) bool {
	return canonicalMAC(left) == canonicalMAC(right)
}

func usableHostAddress(prefix netip.Prefix, address netip.Addr) bool {
	if prefix.Bits() > 30 {
		return true
	}
	network := prefix.Masked().Addr().As4()
	host := address.As4()
	networkValue := uint32(network[0])<<24 | uint32(network[1])<<16 | uint32(network[2])<<8 | uint32(network[3])
	hostValue := uint32(host[0])<<24 | uint32(host[1])<<16 | uint32(host[2])<<8 | uint32(host[3])
	hostBits := 32 - prefix.Bits()
	broadcastValue := networkValue | uint32((uint64(1)<<hostBits)-1)
	return hostValue != networkValue && hostValue != broadcastValue
}
