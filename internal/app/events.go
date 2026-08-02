package app

import (
	"net/netip"
	"time"

	"github.com/amdzy/NetWarden/internal/core"
	"github.com/amdzy/NetWarden/internal/defense"
	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/discovery"
)

type EventKind uint8

const (
	EventDeviceObserved EventKind = iota + 1
	EventDeviceReturnedOnline
	EventDeviceAddressChanged
	EventDeviceIPConflict
	EventDeviceOffline
	EventDeviceRemoved
	EventDeviceMetadataChanged
	EventIntegrityWarning
	EventScanStarted
	EventScanCompleted
	EventScanFailed
	EventRuntimeStarting
	EventRuntimeStarted
	EventRuntimeStopping
	EventRuntimeStopped
	EventPersistenceFailed
	EventRuntimeRebuilding
	EventControlPrepared
	EventControlTargetStateChanged
	EventControlRestorationStarted
	EventControlRestorationCompleted
	EventControlBulkRollbackStarted
	EventControlBulkRollbackCompleted
	EventControlContinuousWorkerStopped
	EventControlAuditFailed
	EventBandwidthMonitoringFailed
)

type ControlState string

const (
	ControlStatePrepared  ControlState = "prepared"
	ControlStateActive    ControlState = "active"
	ControlStateRestoring ControlState = "restoring"
	ControlStateRestored  ControlState = "restored"
	ControlStateFailed    ControlState = "failed"
)

type ControlEvent struct {
	Operation ControlOperation `json:"operation"`
	Targets   []ControlTarget  `json:"targets,omitempty"`
	State     ControlState     `json:"state,omitempty"`
	Reason    string           `json:"reason,omitempty"`
}

type Event struct {
	At         time.Time
	Kind       EventKind
	Device     *device.Device
	Integrity  *defense.Event
	Scan       *discovery.ScanEvent
	Control    *ControlEvent
	Err        error
	Related    *device.Device
	PreviousIP netip.Addr
}

func eventFromCore(event core.Event) Event {
	kind := EventDeviceObserved
	switch event.Kind {
	case core.EventOffline:
		kind = EventDeviceOffline
	case core.EventReturnedOnline:
		kind = EventDeviceReturnedOnline
	case core.EventAddressChanged:
		kind = EventDeviceAddressChanged
	case core.EventIPConflict:
		kind = EventDeviceIPConflict
	case core.EventRemoved:
		kind = EventDeviceRemoved
	case core.EventMetadataChanged:
		kind = EventDeviceMetadataChanged
	}
	snapshot := event.Device
	return Event{Kind: kind, Device: &snapshot, Related: event.Related, PreviousIP: event.PreviousIP}
}

func eventFromScan(event discovery.ScanEvent) Event {
	kind := EventScanStarted
	switch event.Kind {
	case discovery.ScanCompleted:
		kind = EventScanCompleted
	case discovery.ScanFailed:
		kind = EventScanFailed
	}
	copy := event
	return Event{Kind: kind, Scan: &copy, Err: event.Err}
}

func eventFromDefense(event defense.Event) Event {
	copy := event
	return Event{Kind: EventIntegrityWarning, Integrity: &copy}
}
