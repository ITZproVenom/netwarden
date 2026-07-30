package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	coreapp "github.com/amdzy/NetWarden/internal/app"
	"github.com/amdzy/NetWarden/internal/applog"
	"github.com/amdzy/NetWarden/internal/capture/pcapdriver"
	appconfig "github.com/amdzy/NetWarden/internal/config"
	"github.com/amdzy/NetWarden/internal/defense"
	"github.com/amdzy/NetWarden/internal/device"
	"github.com/amdzy/NetWarden/internal/history"
	"github.com/amdzy/NetWarden/internal/metadata"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type GUIApp struct {
	mu         sync.RWMutex
	ctx        context.Context
	supervisor *coreapp.Supervisor
	cancel     context.CancelFunc
	activity   []ActivityDTO
	logger     *slog.Logger
}

type InterfaceDTO struct {
	Name        string   `json:"name"`
	SystemName  string   `json:"systemName"`
	Description string   `json:"description"`
	MAC         string   `json:"mac"`
	Prefixes    []string `json:"prefixes"`
}

type BootstrapDTO struct {
	Interfaces        []InterfaceDTO `json:"interfaces"`
	SelectedInterface string         `json:"selectedInterface"`
	GatewayMAC        string         `json:"gatewayMAC"`
}

type StatusDTO struct {
	coreapp.Status
	ConflictCount int `json:"ConflictCount"`
}

type DeviceDTO struct {
	IP           string    `json:"ip"`
	MAC          string    `json:"mac"`
	Name         string    `json:"name"`
	Vendor       string    `json:"vendor"`
	Type         string    `json:"type"`
	Role         string    `json:"role"`
	FirstSeen    time.Time `json:"firstSeen"`
	LastSeen     time.Time `json:"lastSeen"`
	Online       bool      `json:"online"`
	ControlState string    `json:"controlState"`
}

type ConflictDTO struct {
	GatewayIP  string    `json:"gatewayIP"`
	ClaimedMAC string    `json:"claimedMAC"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
	Count      uint64    `json:"count"`
	Active     bool      `json:"active"`
}

type HistorySummaryDTO struct {
	Devices   int       `json:"devices"`
	Conflicts int       `json:"conflicts"`
	Oldest    time.Time `json:"oldest,omitempty"`
	Newest    time.Time `json:"newest,omitempty"`
}

type ActivityDTO struct {
	At       time.Time `json:"at"`
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail,omitempty"`
}

type AppInfoDTO struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Build   string `json:"build"`
}

func (a *GUIApp) AppInfo() AppInfoDTO {
	return AppInfoDTO{Name: applicationName, Version: applicationVersion, Build: buildVersion}
}

func NewGUIApp() *GUIApp { return &GUIApp{} }

func (a *GUIApp) startup(ctx context.Context) {
	a.ctx = ctx
	a.initializeLogger()
	a.log(slog.LevelInfo, "application started", "component", "lifecycle")
	_, config, err := loadSettings()
	if err != nil || !config.AutoStart || config.Interface == "" {
		return
	}
	go func() {
		if err := a.StartMonitoring(config.Interface); err != nil {
			a.recordActivity(ActivityDTO{At: time.Now().UTC(), Kind: "error", Severity: "error", Title: "Automatic monitoring failed", Detail: err.Error()})
			runtime.EventsEmit(a.ctx, "runtime:error", err.Error())
		}
	}()
}

func (a *GUIApp) shutdown(context.Context) {
	a.log(slog.LevelInfo, "application shutting down", "component", "lifecycle")
	_ = a.StopMonitoring()
}

func (a *GUIApp) Bootstrap() (BootstrapDTO, error) {
	store, config, err := loadSettings()
	_ = store
	if err != nil {
		return BootstrapDTO{}, err
	}
	interfaces, err := pcapdriver.ListInterfaces()
	if err != nil {
		return BootstrapDTO{}, err
	}
	result := BootstrapDTO{SelectedInterface: config.Interface, GatewayMAC: config.GatewayMAC, Interfaces: make([]InterfaceDTO, 0, len(interfaces))}
	for _, candidate := range interfaces {
		item := InterfaceDTO{Name: candidate.Name, SystemName: candidate.SystemName, Description: candidate.Description, MAC: candidate.MAC.String()}
		for _, prefix := range candidate.Prefixes {
			item.Prefixes = append(item.Prefixes, prefix.String())
		}
		result.Interfaces = append(result.Interfaces, item)
	}
	return result, nil
}

func (a *GUIApp) StartMonitoring(interfaceName string) (resultErr error) {
	a.log(slog.LevelInfo, "monitoring requested", "component", "lifecycle", "interface", interfaceName)
	defer func() {
		if resultErr != nil {
			a.log(slog.LevelError, "monitoring failed", "component", "lifecycle", "interface", interfaceName, "error", resultErr)
		}
	}()
	a.mu.Lock()
	if a.cancel != nil {
		a.mu.Unlock()
		return errors.New("monitoring is already running")
	}
	store, config, err := loadSettings()
	if err != nil {
		a.mu.Unlock()
		return err
	}
	selected, err := selectInterface(interfaceName)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	if _, err = store.SetInterface(selected.Name); err != nil {
		a.mu.Unlock()
		return err
	}
	resolver, err := metadata.NewResolver(config.Nicknames)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	ctx, cancel := context.WithCancel(a.ctx)
	dependencies := coreapp.DefaultDependencies()
	if err := configureCapture(ctx, &dependencies); err != nil {
		cancel()
		a.mu.Unlock()
		return err
	}
	dependencies.Metadata = resolver
	dependencies.Settings = store
	dependencies.History = history.NewStore(store.Path() + ".history.json")
	supervisor := coreapp.NewSupervisor(func(factoryContext context.Context) (*coreapp.Runtime, error) {
		_, currentConfig, err := loadSettings()
		if err != nil {
			return nil, err
		}
		fresh, err := selectInterface(selected.Name)
		if err != nil {
			return nil, err
		}
		runtime, err := coreapp.Bootstrap(factoryContext, dependencies, coreapp.Config{
			Interface: fresh, ScanInterval: time.Duration(currentConfig.ScanIntervalSeconds) * time.Second,
			OfflineAfter:     time.Duration(currentConfig.OfflineAfterSeconds) * time.Second,
			HistoryRetention: time.Duration(currentConfig.HistoryRetentionDays) * 24 * time.Hour,
			ProbeDelay:       2 * time.Millisecond, MaximumHosts: 4094, PinnedGatewayMAC: storedMAC(currentConfig.GatewayMAC),
		})
		if err == nil {
			runtime.SetPeriodicScanEnabled(currentConfig.PeriodicDiscovery)
		}
		return runtime, err
	}, time.Second)
	a.supervisor, a.cancel = supervisor, cancel
	a.appendActivityLocked(ActivityDTO{At: time.Now().UTC(), Kind: "lifecycle", Severity: "info", Title: "Monitoring requested", Detail: selected.SystemName})
	a.mu.Unlock()

	go a.forwardEvents(ctx, supervisor)
	go func() {
		err := supervisor.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			a.recordActivity(ActivityDTO{At: time.Now().UTC(), Kind: "error", Severity: "error", Title: "Runtime stopped with an error", Detail: err.Error()})
			runtime.EventsEmit(a.ctx, "runtime:error", err.Error())
		}
		a.mu.Lock()
		if a.supervisor == supervisor {
			a.supervisor, a.cancel = nil, nil
		}
		a.mu.Unlock()
		runtime.EventsEmit(a.ctx, "runtime:changed")
	}()
	return nil
}

func (a *GUIApp) StopMonitoring() error {
	a.log(slog.LevelInfo, "monitoring stop requested", "component", "lifecycle")
	a.mu.RLock()
	cancel := a.cancel
	a.mu.RUnlock()
	if cancel != nil {
		cancel()
	}
	return nil
}

func (a *GUIApp) Status() StatusDTO {
	a.mu.RLock()
	supervisor := a.supervisor
	a.mu.RUnlock()
	if supervisor == nil {
		status := StatusDTO{}
		if snapshot, err := loadHistorySnapshot(); err == nil {
			status.ConflictCount = len(snapshot.Conflicts)
			status.DeviceCount = len(snapshot.Devices)
		}
		return status
	}
	status := supervisor.Status()
	if supervisor.Current() == nil {
		status.Rebuilding = true
	}
	return StatusDTO{Status: status, ConflictCount: len(supervisor.ConflictHistory())}
}

func (a *GUIApp) Devices() ([]DeviceDTO, error) {
	a.mu.RLock()
	supervisor := a.supervisor
	a.mu.RUnlock()
	var devices []device.Device
	if supervisor != nil && supervisor.Current() != nil {
		devices = supervisor.Devices()
	} else {
		snapshot, err := loadHistorySnapshot()
		if err != nil {
			return nil, err
		}
		devices = snapshot.Devices
		_, config, err := loadSettings()
		if err != nil {
			return nil, err
		}
		for index := range devices {
			devices[index].Online = false
			if nickname := config.Nicknames[devices[index].MAC]; nickname != "" {
				devices[index].Name = nickname
			}
		}
	}
	result := make([]DeviceDTO, 0, len(devices))
	activeControl := make(map[string]struct{})
	continuousControl := false
	if supervisor != nil && supervisor.Current() != nil {
		continuousControl = supervisor.Status().ContinuousControl
		for _, target := range supervisor.Current().ControlTargets() {
			activeControl[strings.ToLower(target.MAC.String())] = struct{}{}
		}
	}
	for _, current := range devices {
		item := deviceDTO(current)
		if _, active := activeControl[strings.ToLower(current.MAC)]; active {
			if continuousControl {
				item.ControlState = "continuous"
			} else {
				item.ControlState = "active"
			}
		}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Online != result[j].Online {
			return result[i].Online
		}
		if result[i].Role != result[j].Role {
			return result[i].Role < result[j].Role
		}
		return result[i].IP < result[j].IP
	})
	return result, nil
}

func (a *GUIApp) Conflicts() ([]ConflictDTO, error) {
	a.mu.RLock()
	supervisor := a.supervisor
	a.mu.RUnlock()
	var conflicts []defense.Conflict
	if supervisor != nil && supervisor.Current() != nil {
		conflicts = supervisor.ConflictHistory()
	} else {
		snapshot, err := loadHistorySnapshot()
		if err != nil {
			return nil, err
		}
		conflicts = snapshot.Conflicts
	}
	result := make([]ConflictDTO, 0, len(conflicts))
	for _, conflict := range conflicts {
		result = append(result, ConflictDTO{
			GatewayIP: conflict.GatewayIP.String(), ClaimedMAC: conflict.ClaimedMAC,
			FirstSeen: conflict.FirstSeen, LastSeen: conflict.LastSeen,
			Count: conflict.Count, Active: conflict.Active,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].LastSeen.After(result[j].LastSeen) })
	return result, nil
}

func (a *GUIApp) ScanNow() error {
	supervisor, err := a.activeSupervisor()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	return supervisor.ScanNow(ctx)
}

func (a *GUIApp) SetPeriodicScanEnabled(enabled bool) error {
	supervisor, err := a.activeSupervisor()
	if err != nil {
		return err
	}
	store, config, err := loadSettings()
	if err != nil {
		return err
	}
	settings := config.MonitoringSettings()
	settings.PeriodicDiscovery = enabled
	if _, err := store.SetMonitoringSettings(settings); err != nil {
		return err
	}
	return supervisor.SetPeriodicScanEnabled(enabled)
}

func (a *GUIApp) MonitoringSettings() (appconfig.MonitoringSettings, error) {
	_, config, err := loadSettings()
	if err != nil {
		return appconfig.MonitoringSettings{}, err
	}
	return config.MonitoringSettings(), nil
}

func (a *GUIApp) SetMonitoringSettings(settings appconfig.MonitoringSettings) error {
	if err := a.requireStopped("changing monitoring settings"); err != nil {
		return err
	}
	store, _, err := loadSettings()
	if err != nil {
		return err
	}
	_, err = store.SetMonitoringSettings(settings)
	return err
}

func (a *GUIApp) NotificationSettings() (appconfig.NotificationSettings, error) {
	_, config, err := loadSettings()
	if err != nil {
		return appconfig.NotificationSettings{}, err
	}
	return config.NotificationSettings(), nil
}

func (a *GUIApp) SetNotificationSettings(settings appconfig.NotificationSettings) error {
	store, _, err := loadSettings()
	if err != nil {
		return err
	}
	_, err = store.SetNotificationSettings(settings)
	return err
}

func (a *GUIApp) SetNickname(macAddress, nickname string) error {
	mac, err := net.ParseMAC(macAddress)
	if err != nil {
		return err
	}
	a.mu.RLock()
	supervisor := a.supervisor
	a.mu.RUnlock()
	if supervisor != nil {
		current := supervisor.Current()
		if current == nil {
			return errors.New("runtime is not ready")
		}
		if nickname == "" {
			return current.RemoveNickname(mac)
		}
		return current.SetNickname(mac, nickname)
	}

	store, config, err := loadSettings()
	if err != nil {
		return err
	}
	key := strings.ToLower(mac.String())
	previous := config.Nicknames[key]
	if nickname == "" {
		if _, err := store.RemoveNickname(mac); err != nil {
			return err
		}
	} else if _, err := store.SetNickname(mac, nickname); err != nil {
		return err
	}
	historyStore := history.NewStore(store.Path() + ".history.json")
	snapshot, err := historyStore.Load()
	if err != nil {
		return err
	}
	for index := range snapshot.Devices {
		if snapshot.Devices[index].MAC != key {
			continue
		}
		if nickname != "" {
			snapshot.Devices[index].Name = strings.TrimSpace(nickname)
		} else if previous != "" && snapshot.Devices[index].Name == previous {
			snapshot.Devices[index].Name = snapshot.Devices[index].IP.String()
		}
		break
	}
	return historyStore.Save(snapshot)
}

func (a *GUIApp) SetGatewayMAC(value string) (string, error) {
	a.mu.RLock()
	running := a.supervisor != nil
	a.mu.RUnlock()
	if running {
		return "", errors.New("stop monitoring before changing the trusted gateway identity")
	}
	store, _, err := loadSettings()
	if err != nil {
		return "", err
	}
	if value == "" {
		_, err = store.RemoveGatewayMAC()
		return "", err
	}
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 {
		return "", errors.New("enter a valid 6-byte gateway MAC address")
	}
	config, err := store.SetGatewayMAC(mac)
	return config.GatewayMAC, err
}

func (a *GUIApp) HistorySummary() (HistorySummaryDTO, error) {
	snapshot, err := loadHistorySnapshot()
	if err != nil {
		return HistorySummaryDTO{}, err
	}
	summary := HistorySummaryDTO{Devices: len(snapshot.Devices), Conflicts: len(snapshot.Conflicts)}
	include := func(first, last time.Time) {
		if !first.IsZero() && (summary.Oldest.IsZero() || first.Before(summary.Oldest)) {
			summary.Oldest = first
		}
		if last.After(summary.Newest) {
			summary.Newest = last
		}
	}
	for _, current := range snapshot.Devices {
		include(current.FirstSeen, current.LastSeen)
	}
	for _, current := range snapshot.Conflicts {
		include(current.FirstSeen, current.LastSeen)
	}
	return summary, nil
}

func (a *GUIApp) Activity() []ActivityDTO {
	a.mu.RLock()
	defer a.mu.RUnlock()
	result := make([]ActivityDTO, len(a.activity))
	for index := range a.activity {
		result[len(result)-1-index] = a.activity[index]
	}
	return result
}

func (a *GUIApp) PruneHistory(olderThanDays int) error {
	if olderThanDays <= 0 {
		return errors.New("history age must be a positive number of days")
	}
	if err := a.requireStopped("pruning history"); err != nil {
		return err
	}
	store, _, err := loadSettings()
	if err != nil {
		return err
	}
	historyStore := history.NewStore(store.Path() + ".history.json")
	snapshot, err := historyStore.Load()
	if err != nil {
		return err
	}
	return historyStore.Save(history.Prune(snapshot, time.Now().UTC().Add(-time.Duration(olderThanDays)*24*time.Hour)))
}

func (a *GUIApp) ClearHistory() error {
	if err := a.requireStopped("clearing history"); err != nil {
		return err
	}
	store, _, err := loadSettings()
	if err != nil {
		return err
	}
	return history.NewStore(store.Path() + ".history.json").Clear()
}

func (a *GUIApp) requireStopped(action string) error {
	a.mu.RLock()
	running := a.supervisor != nil
	a.mu.RUnlock()
	if running {
		return fmt.Errorf("stop monitoring before %s", action)
	}
	return nil
}

func (a *GUIApp) activeSupervisor() (*coreapp.Supervisor, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.supervisor == nil {
		return nil, errors.New("monitoring is not running")
	}
	return a.supervisor, nil
}

func (a *GUIApp) forwardEvents(ctx context.Context, supervisor *coreapp.Supervisor) {
	baselineComplete := false
	baselineNew := make(map[string]struct{})
	baselineKnown := make(map[string]struct{})
	var baselineTimer *time.Timer
	var baselineReady <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			if baselineTimer != nil {
				baselineTimer.Stop()
			}
			return
		case <-baselineReady:
			baselineComplete = true
			baselineReady = nil
			if title, body, notify := a.baselineNotification(len(baselineNew), len(baselineKnown)); notify {
				go a.sendNotification(title, body)
			}
		case event := <-supervisor.Events():
			activity := activityFromEvent(event)
			a.recordActivity(activity)
			runtime.EventsEmit(a.ctx, "network:event", activity)
			if !baselineComplete {
				switch event.Kind {
				case coreapp.EventDeviceObserved:
					if event.Device != nil {
						baselineNew[event.Device.MAC] = struct{}{}
						delete(baselineKnown, event.Device.MAC)
					}
				case coreapp.EventDeviceReturnedOnline:
					if event.Device != nil {
						if _, isNew := baselineNew[event.Device.MAC]; !isNew {
							baselineKnown[event.Device.MAC] = struct{}{}
						}
					}
				case coreapp.EventScanCompleted:
					// Allow replies to the final probes to reach the event stream before
					// producing the one startup summary.
					baselineTimer = time.NewTimer(2 * time.Second)
					baselineReady = baselineTimer.C
				case coreapp.EventScanFailed:
					// A failed initial scan must not suppress alerts for the rest of the session.
					baselineComplete = true
				}
				if !baselineComplete || event.Kind == coreapp.EventScanCompleted || event.Kind == coreapp.EventScanFailed {
					if isSuspiciousEvent(event) && a.shouldNotify(event) {
						title, body := notificationContent(event, activity)
						go a.sendNotification(title, body)
					}
					continue
				}
			}
			if a.shouldNotify(event) {
				title, body := notificationContent(event, activity)
				go a.sendNotification(title, body)
			}
		}
	}
}

func (a *GUIApp) sendNotification(title, body string) {
	if err := sendNativeNotification(title, body); err != nil {
		a.log(slog.LevelWarn, "native notification failed", "component", "notification", "error", err)
	}
}

func (a *GUIApp) baselineNotification(newDevices, knownDevices int) (string, string, bool) {
	_, config, err := loadSettings()
	if err != nil {
		return "", "", false
	}
	return baselineNotificationContent(config.NotificationSettings(), newDevices, knownDevices)
}

func baselineNotificationContent(settings appconfig.NotificationSettings, newDevices, knownDevices int) (string, string, bool) {
	if !settings.Enabled {
		return "", "", false
	}
	parts := make([]string, 0, 2)
	if settings.NewDevices && newDevices > 0 {
		parts = append(parts, fmt.Sprintf("%d new %s", newDevices, pluralize("device", newDevices)))
	}
	if settings.KnownDevices && knownDevices > 0 {
		parts = append(parts, fmt.Sprintf("%d known %s", knownDevices, pluralize("device", knownDevices)))
	}
	if len(parts) == 0 {
		return "", "", false
	}
	return "Initial network scan complete", strings.Join(parts, " · "), true
}

func pluralize(word string, count int) string {
	if count == 1 {
		return word
	}
	return word + "s"
}

func isSuspiciousEvent(event coreapp.Event) bool {
	if event.Kind == coreapp.EventIntegrityWarning || event.Kind == coreapp.EventDeviceIPConflict {
		return true
	}
	return event.Kind == coreapp.EventControlRestorationCompleted && event.Control != nil && event.Control.State == coreapp.ControlStateFailed
}

func notificationContent(event coreapp.Event, activity ActivityDTO) (string, string) {
	if event.Device == nil {
		return activity.Title, activity.Detail
	}
	current := event.Device
	label := strings.TrimSpace(current.Name)
	if label == "" || label == current.IP.String() {
		label = strings.TrimSpace(current.Vendor)
	}
	if label == "" || strings.EqualFold(label, "unknown") {
		return activity.Title, fmt.Sprintf("%s · %s", current.IP, current.MAC)
	}
	return activity.Title, fmt.Sprintf("%s\n%s · %s", label, current.IP, current.MAC)
}

func (a *GUIApp) shouldNotify(event coreapp.Event) bool {
	_, config, err := loadSettings()
	if err != nil || !config.NotificationsEnabled {
		return false
	}
	switch event.Kind {
	case coreapp.EventDeviceObserved:
		return config.NotifyNewDevices
	case coreapp.EventDeviceReturnedOnline:
		return config.NotifyKnownDevices
	case coreapp.EventDeviceOffline:
		return config.NotifyDeviceOffline
	case coreapp.EventIntegrityWarning, coreapp.EventDeviceIPConflict:
		return config.NotifySuspicious
	case coreapp.EventControlRestorationCompleted:
		return config.NotifySuspicious && event.Control != nil && event.Control.State == coreapp.ControlStateFailed
	default:
		return false
	}
}

func (a *GUIApp) recordActivity(event ActivityDTO) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.appendActivityLocked(event)
	level := slog.LevelInfo
	if event.Severity == "warning" {
		level = slog.LevelWarn
	}
	if event.Severity == "error" {
		level = slog.LevelError
	}
	a.log(level, event.Title, "component", event.Kind, "detail", event.Detail, "at", event.At)
}

func (a *GUIApp) initializeLogger() {
	path, err := appconfig.DefaultPath()
	if err != nil {
		return
	}
	writer, err := applog.Open(filepath.Join(filepath.Dir(path), "logs", "netwarden.jsonl"), applog.Options{})
	if err != nil {
		return
	}
	a.logger = slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func (a *GUIApp) log(level slog.Level, message string, attributes ...any) {
	if a.logger != nil {
		a.logger.Log(context.Background(), level, message, attributes...)
	}
}

func (a *GUIApp) appendActivityLocked(event ActivityDTO) {
	const maximumActivity = 250
	if event.At.IsZero() {
		event.At = time.Now().UTC()
	}
	a.activity = append(a.activity, event)
	if len(a.activity) > maximumActivity {
		copy(a.activity, a.activity[len(a.activity)-maximumActivity:])
		a.activity = a.activity[:maximumActivity]
	}
}

func activityFromEvent(event coreapp.Event) ActivityDTO {
	activity := ActivityDTO{At: event.At, Kind: "runtime", Severity: "info", Title: "Runtime event"}
	if event.Err != nil {
		activity.Detail = event.Err.Error()
	}
	switch event.Kind {
	case coreapp.EventDeviceObserved:
		activity.Kind, activity.Title = "device", "New device joined"
	case coreapp.EventDeviceReturnedOnline:
		activity.Kind, activity.Title = "device", "Device returned online"
	case coreapp.EventDeviceAddressChanged:
		activity.Kind, activity.Title = "device", "Device address changed"
	case coreapp.EventDeviceIPConflict:
		activity.Kind, activity.Severity, activity.Title = "device", "warning", "IP address conflict"
	case coreapp.EventDeviceOffline:
		activity.Kind, activity.Title = "device", "Known device left"
	case coreapp.EventDeviceRemoved:
		activity.Kind, activity.Title = "device", "Stale device removed"
	case coreapp.EventDeviceMetadataChanged:
		activity.Kind, activity.Title = "device", "Device metadata updated"
	case coreapp.EventIntegrityWarning:
		activity.Kind, activity.Severity, activity.Title = "integrity", "warning", "Gateway integrity changed"
	case coreapp.EventScanStarted:
		activity.Kind, activity.Title = "scan", "Discovery scan started"
	case coreapp.EventScanCompleted:
		activity.Kind, activity.Title = "scan", "Discovery scan completed"
	case coreapp.EventScanFailed:
		activity.Kind, activity.Severity, activity.Title = "scan", "error", "Discovery scan failed"
	case coreapp.EventRuntimeStarting:
		activity.Title = "Runtime starting"
	case coreapp.EventRuntimeStarted:
		activity.Title = "Runtime started"
	case coreapp.EventRuntimeStopping:
		activity.Title = "Runtime stopping"
	case coreapp.EventRuntimeStopped:
		activity.Title = "Runtime stopped"
	case coreapp.EventPersistenceFailed:
		activity.Kind, activity.Severity, activity.Title = "persistence", "error", "History persistence failed"
	case coreapp.EventRuntimeRebuilding:
		activity.Kind, activity.Severity, activity.Title = "runtime", "warning", "Runtime rebuilding"
	case coreapp.EventControlPrepared:
		activity.Kind, activity.Title = "control", "Control request prepared"
	case coreapp.EventControlTargetStateChanged:
		activity.Kind, activity.Severity, activity.Title = "control", "warning", "Control target state changed"
	case coreapp.EventControlRestorationStarted:
		activity.Kind, activity.Title = "control", "Control restoration started"
	case coreapp.EventControlRestorationCompleted:
		activity.Kind, activity.Title = "control", "Control restoration completed"
		if event.Control != nil && event.Control.State == coreapp.ControlStateFailed {
			activity.Severity, activity.Title = "error", "Control restoration failed"
		}
	case coreapp.EventControlBulkRollbackStarted:
		activity.Kind, activity.Severity, activity.Title = "control", "warning", "Bulk control rollback started"
	case coreapp.EventControlBulkRollbackCompleted:
		activity.Kind, activity.Title = "control", "Bulk control rollback completed"
	case coreapp.EventControlContinuousWorkerStopped:
		activity.Kind, activity.Title = "control", "Continuous control stopped"
	case coreapp.EventControlAuditFailed:
		activity.Kind, activity.Severity, activity.Title = "control", "error", "Control audit failed"
	}
	if event.Device != nil {
		parts := make([]string, 0, 3)
		if name := strings.TrimSpace(event.Device.Name); name != "" && name != event.Device.IP.String() {
			parts = append(parts, name)
		}
		parts = append(parts, event.Device.IP.String(), event.Device.MAC)
		activity.Detail = strings.Join(parts, " · ")
	}
	if event.Scan != nil {
		activity.Detail = fmt.Sprintf("%s · %d addresses · %s", event.Scan.Prefix.Masked(), event.Scan.Probed, event.Scan.Duration.Round(time.Millisecond))
		if event.Scan.Err != nil {
			activity.Detail = event.Scan.Err.Error()
		}
	}
	if event.Integrity != nil {
		activity.Detail = fmt.Sprintf("gateway %s · expected %s · claimed %s", event.Integrity.GatewayIP, event.Integrity.ExpectedMAC, event.Integrity.ClaimedMAC)
	}
	if event.Control != nil {
		activity.Detail = fmt.Sprintf("%s · %s · %d targets", event.Control.Operation, event.Control.State, len(event.Control.Targets))
		if event.Control.Reason != "" {
			activity.Detail += " · " + event.Control.Reason
		}
	}
	return activity
}

func loadSettings() (*appconfig.Store, appconfig.Config, error) {
	path, err := appconfig.DefaultPath()
	if err != nil {
		return nil, appconfig.Config{}, err
	}
	store := appconfig.NewStore(path)
	config, err := store.Load()
	return store, config, err
}

func loadHistorySnapshot() (history.Snapshot, error) {
	store, _, err := loadSettings()
	if err != nil {
		return history.Snapshot{}, err
	}
	return history.NewStore(store.Path() + ".history.json").Load()
}

func selectInterface(name string) (pcapdriver.Interface, error) {
	interfaces, err := pcapdriver.ListInterfaces()
	if err != nil {
		return pcapdriver.Interface{}, err
	}
	return pcapdriver.SelectInterface(interfaces, name)
}

func storedMAC(value string) net.HardwareAddr {
	mac, _ := net.ParseMAC(value)
	return mac
}

func deviceDTO(value device.Device) DeviceDTO {
	roles := map[device.Role]string{device.RolePeer: "Device", device.RoleLocal: "This device", device.RoleGateway: "Gateway"}
	deviceType := value.Type
	if deviceType == "" {
		deviceType = device.TypeUnknown
	}
	return DeviceDTO{IP: value.IP.String(), MAC: value.MAC, Name: value.Name, Vendor: value.Vendor, Type: string(deviceType), Role: roles[value.Role], FirstSeen: value.FirstSeen, LastSeen: value.LastSeen, Online: value.Online}
}
