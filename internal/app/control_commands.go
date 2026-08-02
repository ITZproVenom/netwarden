package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/amdzy/NetWarden/internal/control"
	"github.com/amdzy/NetWarden/internal/device"
)

var (
	ErrControlRegistryUnavailable   = errors.New("control device registry is unavailable")
	ErrNoEligibleTargets            = errors.New("no eligible control targets")
	ErrControlControllerUnavailable = errors.New("control controller is unavailable")
)

type ControlOperation string

const (
	ControlDisconnect     ControlOperation = "disconnect"
	ControlDisconnectAll  ControlOperation = "disconnect_all"
	ControlContinuous     ControlOperation = "continuous"
	ControlRestore        ControlOperation = "restore"
	ControlRestoreAll     ControlOperation = "restore_all"
	ControlStopContinuous ControlOperation = "stop_continuous"
)

type ControlTarget struct {
	IP  netip.Addr       `json:"ip"`
	MAC net.HardwareAddr `json:"mac"`
}

type ControlRequest struct {
	Operation ControlOperation `json:"operation"`
	Targets   []ControlTarget  `json:"targets"`
}

type ControlAuditEvent struct {
	At        time.Time        `json:"at"`
	Operation ControlOperation `json:"operation"`
	Targets   []ControlTarget  `json:"targets"`
	Outcome   string           `json:"outcome"`
}

type ControlDeviceSource interface{ Snapshot() []device.Device }
type ControlAuditor interface {
	Record(context.Context, ControlAuditEvent) error
}
type ControlControllerFactory interface {
	Prepare(context.Context, ControlRequest, ControlScope) (ControlControllerLease, error)
}

type ControlController interface {
	Isolate(context.Context, control.Endpoint) error
	Restore(context.Context, control.Endpoint) error
	Run(context.Context) error
}

type ControlControllerLease struct {
	Controller ControlController
	Close      func() error
}

type ControlScope struct {
	Prefix     netip.Prefix
	LocalIP    netip.Addr
	LocalMAC   net.HardwareAddr
	GatewayIP  netip.Addr
	GatewayMAC net.HardwareAddr
}

type ControlDependencies struct {
	Devices           ControlDeviceSource
	Scope             ControlScope
	Auditor           ControlAuditor
	ControllerFactory ControlControllerFactory
	Lifecycle         *ControlLifecycle
	Publish           func(Event)
	DisruptiveGuard   func(ControlTarget) error
}

type ControlCommands struct {
	controller ControlController
	deps       ControlDependencies
}

func NewControlCommands(controller ControlController, dependencies ControlDependencies) *ControlCommands {
	return &ControlCommands{controller: controller, deps: dependencies}
}

func (c *ControlCommands) Disconnect(ctx context.Context, target ControlTarget) error {
	eligible, err := c.resolveTarget(target)
	if err != nil {
		return err
	}
	if err := c.guardDisruptive(eligible); err != nil {
		return err
	}
	return c.prepare(ctx, ControlRequest{Operation: ControlDisconnect, Targets: []ControlTarget{eligible}})
}

func (c *ControlCommands) DisconnectAll(ctx context.Context) error {
	targets, err := c.eligiblePeers()
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return ErrNoEligibleTargets
	}
	return c.prepare(ctx, ControlRequest{Operation: ControlDisconnectAll, Targets: targets})
}

// DisconnectSelected validates the requested snapshot against current registry
// state before preparing one rollback-safe bulk operation.
func (c *ControlCommands) DisconnectSelected(ctx context.Context, requested []ControlTarget) error {
	if len(requested) == 0 {
		return ErrNoEligibleTargets
	}
	targets := make([]ControlTarget, 0, len(requested))
	for _, target := range requested {
		resolved, err := c.resolveTarget(target)
		if err != nil {
			return err
		}
		if err := c.guardDisruptive(resolved); err != nil {
			return err
		}
		targets = append(targets, resolved)
	}
	return c.prepare(ctx, ControlRequest{Operation: ControlDisconnectAll, Targets: targets})
}

func (c *ControlCommands) StartContinuous(ctx context.Context, target ControlTarget) error {
	eligible, err := c.resolveTarget(target)
	if err != nil {
		return err
	}
	if err := c.guardDisruptive(eligible); err != nil {
		return err
	}
	return c.prepare(ctx, ControlRequest{Operation: ControlContinuous, Targets: []ControlTarget{eligible}})
}

// Restore is a recovery operation. It deliberately bypasses disruptive-action
// authorization and confirmation, but still validates scope and records the result.
func (c *ControlCommands) Restore(ctx context.Context, target ControlTarget) error {
	resolved, err := c.resolveRecoveryTarget(target)
	if err != nil {
		return err
	}
	return c.restore(ctx, ControlRestore, []ControlTarget{resolved})
}

func (c *ControlCommands) RestoreAll(ctx context.Context) error {
	var targets []ControlTarget
	if c.deps.Lifecycle != nil {
		targets = c.deps.Lifecycle.Snapshot()
	} else {
		var err error
		targets, err = c.recoveryPeers()
		if err != nil {
			return err
		}
	}
	if len(targets) == 0 {
		return ErrNoEligibleTargets
	}
	return c.restore(ctx, ControlRestoreAll, targets)
}

func (c *ControlCommands) StopContinuous(ctx context.Context, target ControlTarget) error {
	resolved, err := c.resolveRecoveryTarget(target)
	if err != nil {
		return err
	}
	return c.restore(ctx, ControlStopContinuous, []ControlTarget{resolved})
}

func (c *ControlCommands) restore(ctx context.Context, operation ControlOperation, targets []ControlTarget) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.controller == nil && c.deps.Lifecycle == nil {
		return ErrControlControllerUnavailable
	}
	var restoreErrors []error
	if c.deps.Lifecycle != nil {
		var err error
		switch operation {
		case ControlRestore:
			err = c.deps.Lifecycle.Restore(ctx, targets[0], "requested by user")
		case ControlRestoreAll, ControlStopContinuous:
			err = c.deps.Lifecycle.RestoreAll(ctx, "requested by user")
		default:
			err = errors.New("unsupported recovery operation")
		}
		if err != nil {
			restoreErrors = append(restoreErrors, err)
		}
	} else {
		for _, target := range targets {
			endpoint, err := controlEndpoint(target)
			if err == nil {
				err = c.controller.Restore(ctx, endpoint)
			}
			if err != nil {
				restoreErrors = append(restoreErrors, err)
			}
		}
	}
	outcome := "restored"
	if len(restoreErrors) > 0 {
		outcome = "restore_failed"
	}
	if c.deps.Auditor == nil {
		err := errors.New("control audit log is unavailable")
		restoreErrors = append(restoreErrors, err)
		c.publishAuditFailure(ControlRequest{Operation: operation, Targets: targets}, err)
	} else if err := c.deps.Auditor.Record(ctx, ControlAuditEvent{
		At: time.Now().UTC(), Operation: operation, Targets: cloneTargets(targets), Outcome: outcome,
	}); err != nil {
		restoreErrors = append(restoreErrors, fmt.Errorf("record recovery audit: %w", err))
		c.publishAuditFailure(ControlRequest{Operation: operation, Targets: targets}, err)
	}
	return errors.Join(restoreErrors...)
}

func (c *ControlCommands) prepare(ctx context.Context, request ControlRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.deps.Auditor == nil {
		err := errors.New("control audit log is unavailable")
		c.publishAuditFailure(request, err)
		return err
	}
	request.Targets = sortedUniqueTargets(request.Targets)
	endpoints := make([]control.Endpoint, 0, len(request.Targets))
	for _, target := range request.Targets {
		endpoint, err := controlEndpoint(target)
		if err != nil {
			return err
		}
		endpoints = append(endpoints, endpoint)
	}
	lease := ControlControllerLease{}
	reusedLifecycleController := false
	if c.controller != nil {
		lease.Controller = c.controller
	}
	if lease.Controller == nil && c.deps.Lifecycle != nil {
		lease.Controller = c.deps.Lifecycle.Controller()
		reusedLifecycleController = lease.Controller != nil
	}
	if lease.Controller == nil {
		if c.deps.ControllerFactory == nil {
			return ErrControlControllerUnavailable
		}
		var err error
		lease, err = c.deps.ControllerFactory.Prepare(ctx, cloneControlRequest(request), c.deps.Scope)
		if err != nil {
			return fmt.Errorf("prepare control controller: %w", err)
		}
	}
	if lease.Controller == nil {
		return ErrControlControllerUnavailable
	}
	owned := false
	defer func() {
		if !owned && lease.Close != nil {
			_ = lease.Close()
		}
	}()
	event := ControlAuditEvent{At: time.Now().UTC(), Operation: request.Operation, Targets: cloneTargets(request.Targets), Outcome: "requested"}
	if err := c.deps.Auditor.Record(ctx, event); err != nil {
		c.publishAuditFailure(request, err)
		return fmt.Errorf("record control audit: %w", err)
	}
	if c.deps.Lifecycle != nil {
		c.deps.Lifecycle.Prepared(request)
	} else if c.deps.Publish != nil {
		c.deps.Publish(Event{Kind: EventControlPrepared, Control: &ControlEvent{Operation: request.Operation, Targets: cloneTargets(request.Targets), State: ControlStatePrepared}})
	}

	isolated := make([]ControlTarget, 0, len(request.Targets))
	for index, endpoint := range endpoints {
		if reusedLifecycleController && lifecycleContainsTarget(c.deps.Lifecycle, request.Targets[index]) {
			continue
		}
		if err := lease.Controller.Isolate(ctx, endpoint); err != nil {
			c.publishPreparedRollback(EventControlBulkRollbackStarted, isolated, ControlStateRestoring, err)
			rollbackErr := restorePreparedTargets(lease.Controller, isolated)
			state := ControlStateRestored
			if rollbackErr != nil {
				state = ControlStateFailed
			}
			c.publishPreparedRollback(EventControlBulkRollbackCompleted, isolated, state, rollbackErr)
			failure := errors.Join(fmt.Errorf("isolate target %s: %w", request.Targets[index].IP, err), rollbackErr)
			_ = c.recordControlOutcome(ctx, request, outcomeForRollback(rollbackErr))
			return failure
		}
		isolated = append(isolated, request.Targets[index])
	}
	if c.deps.Lifecycle == nil {
		rollbackErr := restorePreparedTargets(lease.Controller, isolated)
		_ = c.recordControlOutcome(ctx, request, outcomeForRollback(rollbackErr))
		return errors.Join(errors.New("control lifecycle is unavailable"), rollbackErr)
	}
	continuous := request.Operation == ControlContinuous
	var adoptErr error
	if reusedLifecycleController {
		adoptErr = c.deps.Lifecycle.ExtendActive(request.Operation, request.Targets, continuous)
	} else {
		adoptErr = c.deps.Lifecycle.AdoptActive(lease, request.Operation, request.Targets, continuous)
	}
	if adoptErr != nil {
		rollbackErr := restorePreparedTargets(lease.Controller, isolated)
		_ = c.recordControlOutcome(ctx, request, outcomeForRollback(rollbackErr))
		return errors.Join(fmt.Errorf("adopt active control: %w", adoptErr), rollbackErr)
	}
	owned = true
	if err := c.recordControlOutcome(ctx, request, "active"); err != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return errors.Join(err, c.deps.Lifecycle.RestoreAll(cleanupCtx, "control outcome audit failed"))
	}
	return nil
}

func lifecycleContainsTarget(lifecycle *ControlLifecycle, target ControlTarget) bool {
	if lifecycle == nil {
		return false
	}
	wanted := controlTargetKey(target)
	for _, active := range lifecycle.Snapshot() {
		if controlTargetKey(active) == wanted {
			return true
		}
	}
	return false
}

func (c *ControlCommands) publishPreparedRollback(kind EventKind, targets []ControlTarget, state ControlState, err error) {
	if c.deps.Publish == nil || len(targets) == 0 {
		return
	}
	c.deps.Publish(Event{Kind: kind, Control: &ControlEvent{Operation: ControlDisconnectAll, Targets: cloneTargets(targets), State: state, Reason: errorReason("partial control rollback", err)}})
}

func (c *ControlCommands) recordControlOutcome(ctx context.Context, request ControlRequest, outcome string) error {
	if err := c.deps.Auditor.Record(ctx, ControlAuditEvent{At: time.Now().UTC(), Operation: request.Operation, Targets: cloneTargets(request.Targets), Outcome: outcome}); err != nil {
		c.publishAuditFailure(request, err)
		return fmt.Errorf("record control outcome: %w", err)
	}
	return nil
}

func restorePreparedTargets(controller ControlController, targets []ControlTarget) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var failures []error
	for index := len(targets) - 1; index >= 0; index-- {
		endpoint, err := controlEndpoint(targets[index])
		if err == nil {
			err = controller.Restore(cleanupCtx, endpoint)
		}
		if err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func outcomeForRollback(err error) string {
	if err != nil {
		return "rollback_failed"
	}
	return "rolled_back"
}

func (c *ControlCommands) publishAuditFailure(request ControlRequest, err error) {
	if c.deps.Publish != nil {
		c.deps.Publish(Event{Kind: EventControlAuditFailed, Err: err, Control: &ControlEvent{Operation: request.Operation, Targets: cloneTargets(request.Targets), State: ControlStateFailed, Reason: err.Error()}})
	}
}

func (c *ControlCommands) resolveTarget(target ControlTarget) (ControlTarget, error) {
	if _, err := controlEndpoint(target); err != nil {
		return ControlTarget{}, err
	}
	if c.deps.Devices == nil {
		return ControlTarget{}, ErrControlRegistryUnavailable
	}
	wantedMAC := strings.ToLower(target.MAC.String())
	for _, current := range c.deps.Devices.Snapshot() {
		if current.IP == target.IP && strings.ToLower(current.MAC) == wantedMAC {
			if !c.eligibleDevice(current) {
				return ControlTarget{}, errors.New("target is not an eligible online peer")
			}
			return cloneTarget(target), nil
		}
	}
	return ControlTarget{}, errors.New("target was not found in the device registry")
}

func (c *ControlCommands) resolveRecoveryTarget(target ControlTarget) (ControlTarget, error) {
	if _, err := controlEndpoint(target); err != nil {
		return ControlTarget{}, err
	}
	if c.deps.Devices == nil {
		return ControlTarget{}, ErrControlRegistryUnavailable
	}
	wantedMAC := strings.ToLower(target.MAC.String())
	for _, current := range c.deps.Devices.Snapshot() {
		if current.IP == target.IP && strings.ToLower(current.MAC) == wantedMAC {
			if !c.recoveryDevice(current) {
				return ControlTarget{}, errors.New("target is not an eligible recovery peer")
			}
			return cloneTarget(target), nil
		}
	}
	return ControlTarget{}, errors.New("target was not found in the device registry")
}

func (c *ControlCommands) eligiblePeers() ([]ControlTarget, error) {
	if c.deps.Devices == nil {
		return nil, ErrControlRegistryUnavailable
	}
	var targets []ControlTarget
	for _, current := range c.deps.Devices.Snapshot() {
		if !c.eligibleDevice(current) {
			continue
		}
		mac, err := net.ParseMAC(current.MAC)
		if err != nil || len(mac) != 6 {
			continue
		}
		targets = append(targets, ControlTarget{IP: current.IP, MAC: mac})
		if err := c.guardDisruptive(targets[len(targets)-1]); err != nil {
			targets = targets[:len(targets)-1]
		}
	}
	return targets, nil
}

func (c *ControlCommands) guardDisruptive(target ControlTarget) error {
	if c.deps.DisruptiveGuard == nil {
		return nil
	}
	return c.deps.DisruptiveGuard(cloneTarget(target))
}

func (c *ControlCommands) recoveryPeers() ([]ControlTarget, error) {
	if c.deps.Devices == nil {
		return nil, ErrControlRegistryUnavailable
	}
	var targets []ControlTarget
	for _, current := range c.deps.Devices.Snapshot() {
		if !c.recoveryDevice(current) {
			continue
		}
		mac, err := net.ParseMAC(current.MAC)
		if err == nil && len(mac) == 6 {
			targets = append(targets, ControlTarget{IP: current.IP, MAC: mac})
		}
	}
	return targets, nil
}

func (c *ControlCommands) eligibleDevice(current device.Device) bool {
	return current.Online && c.recoveryDevice(current)
}

func (c *ControlCommands) recoveryDevice(current device.Device) bool {
	scope := c.deps.Scope
	if current.Role != device.RolePeer || !scope.Prefix.IsValid() {
		return false
	}
	if current.IP.Is4() && (!scope.Prefix.Contains(current.IP) || !usableControlHost(scope.Prefix, current.IP)) {
		return false
	}
	if !current.IP.Is4() && (!current.IP.Is6() || current.IP.IsUnspecified() || current.IP.IsMulticast() || current.IP.IsLoopback()) {
		return false
	}
	if current.IP == scope.LocalIP || current.IP == scope.GatewayIP {
		return false
	}
	mac, err := net.ParseMAC(current.MAC)
	if err != nil || len(mac) != 6 {
		return false
	}
	if strings.EqualFold(mac.String(), scope.LocalMAC.String()) || strings.EqualFold(mac.String(), scope.GatewayMAC.String()) {
		return false
	}
	_, err = controlEndpoint(ControlTarget{IP: current.IP, MAC: mac})
	return err == nil
}

func controlEndpoint(target ControlTarget) (control.Endpoint, error) {
	if !target.IP.IsValid() || target.IP.IsUnspecified() || target.IP.IsMulticast() || target.IP.IsLoopback() {
		return control.Endpoint{}, errors.New("a valid target unicast address is required")
	}
	if len(target.MAC) != 6 || target.MAC[0]&1 != 0 {
		return control.Endpoint{}, errors.New("a 6-byte unicast target MAC is required")
	}
	zero := true
	for _, octet := range target.MAC {
		zero = zero && octet == 0
	}
	if zero {
		return control.Endpoint{}, errors.New("target MAC cannot be zero")
	}
	return control.Endpoint{IP: target.IP, MAC: append(net.HardwareAddr(nil), target.MAC...)}, nil
}

func cloneControlRequest(request ControlRequest) ControlRequest {
	request.Targets = cloneTargets(request.Targets)
	return request
}
func cloneTargets(targets []ControlTarget) []ControlTarget {
	result := make([]ControlTarget, len(targets))
	for i, target := range targets {
		result[i] = cloneTarget(target)
	}
	return result
}
func cloneTarget(target ControlTarget) ControlTarget {
	target.MAC = append(net.HardwareAddr(nil), target.MAC...)
	return target
}

func sortedUniqueTargets(targets []ControlTarget) []ControlTarget {
	unique := make(map[string]ControlTarget, len(targets))
	for _, target := range targets {
		key := target.IP.String() + "/" + strings.ToLower(target.MAC.String())
		unique[key] = cloneTarget(target)
	}
	result := make([]ControlTarget, 0, len(unique))
	for _, target := range unique {
		result = append(result, target)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].IP == result[j].IP {
			return result[i].MAC.String() < result[j].MAC.String()
		}
		return result[i].IP.Less(result[j].IP)
	})
	return result
}

func usableControlHost(prefix netip.Prefix, address netip.Addr) bool {
	if !prefix.IsValid() || !address.Is4() || !prefix.Masked().Contains(address) {
		return false
	}
	if prefix.Bits() > 30 {
		return true
	}
	network := prefix.Masked().Addr().As4()
	host := address.As4()
	networkValue := uint32(network[0])<<24 | uint32(network[1])<<16 | uint32(network[2])<<8 | uint32(network[3])
	hostValue := uint32(host[0])<<24 | uint32(host[1])<<16 | uint32(host[2])<<8 | uint32(host[3])
	broadcastValue := networkValue | uint32((uint64(1)<<(32-prefix.Bits()))-1)
	return hostValue != networkValue && hostValue != broadcastValue
}
