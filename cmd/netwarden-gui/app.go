package main

import (
	"context"
	"errors"
	"net"
	"sort"
	"sync"
	"time"

	coreapp "github.com/amdzy/NetWarden/internal/app"
	"github.com/amdzy/NetWarden/internal/capture/pcapdriver"
	appconfig "github.com/amdzy/NetWarden/internal/config"
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
}

type StatusDTO struct {
	coreapp.Status
	ConflictCount int `json:"ConflictCount"`
}

type DeviceDTO struct {
	IP        string    `json:"ip"`
	MAC       string    `json:"mac"`
	Name      string    `json:"name"`
	Vendor    string    `json:"vendor"`
	Role      string    `json:"role"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	Online    bool      `json:"online"`
}

type ConflictDTO struct {
	GatewayIP  string    `json:"gatewayIP"`
	ClaimedMAC string    `json:"claimedMAC"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
	Count      uint64    `json:"count"`
	Active     bool      `json:"active"`
}

func NewGUIApp() *GUIApp { return &GUIApp{} }

func (a *GUIApp) startup(ctx context.Context) { a.ctx = ctx }

func (a *GUIApp) shutdown(context.Context) { _ = a.StopMonitoring() }

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
	result := BootstrapDTO{SelectedInterface: config.Interface, Interfaces: make([]InterfaceDTO, 0, len(interfaces))}
	for _, candidate := range interfaces {
		item := InterfaceDTO{Name: candidate.Name, SystemName: candidate.SystemName, Description: candidate.Description, MAC: candidate.MAC.String()}
		for _, prefix := range candidate.Prefixes {
			item.Prefixes = append(item.Prefixes, prefix.String())
		}
		result.Interfaces = append(result.Interfaces, item)
	}
	return result, nil
}

func (a *GUIApp) StartMonitoring(interfaceName string) error {
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
	dependencies.Metadata = resolver
	dependencies.Settings = store
	dependencies.History = history.NewStore(store.Path() + ".history.json")
	supervisor := coreapp.NewSupervisor(func(factoryContext context.Context) (*coreapp.Runtime, error) {
		fresh, err := selectInterface(selected.Name)
		if err != nil {
			return nil, err
		}
		return coreapp.Bootstrap(factoryContext, dependencies, coreapp.Config{
			Interface: fresh, ScanInterval: 10 * time.Second, ProbeDelay: 2 * time.Millisecond,
			MaximumHosts: 4094, PinnedGatewayMAC: storedMAC(config.GatewayMAC),
		})
	}, time.Second)
	a.supervisor, a.cancel = supervisor, cancel
	a.mu.Unlock()

	go a.forwardEvents(ctx, supervisor)
	go func() {
		err := supervisor.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
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
		return StatusDTO{}
	}
	status := supervisor.Status()
	if supervisor.Current() == nil {
		status.Rebuilding = true
	}
	return StatusDTO{Status: status, ConflictCount: len(supervisor.ConflictHistory())}
}

func (a *GUIApp) Devices() []DeviceDTO {
	a.mu.RLock()
	supervisor := a.supervisor
	a.mu.RUnlock()
	if supervisor == nil {
		return []DeviceDTO{}
	}
	devices := supervisor.Devices()
	result := make([]DeviceDTO, 0, len(devices))
	for _, current := range devices {
		result = append(result, deviceDTO(current))
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
	return result
}

func (a *GUIApp) Conflicts() []ConflictDTO {
	a.mu.RLock()
	supervisor := a.supervisor
	a.mu.RUnlock()
	if supervisor == nil {
		return []ConflictDTO{}
	}
	conflicts := supervisor.ConflictHistory()
	result := make([]ConflictDTO, 0, len(conflicts))
	for _, conflict := range conflicts {
		result = append(result, ConflictDTO{
			GatewayIP: conflict.GatewayIP.String(), ClaimedMAC: conflict.ClaimedMAC,
			FirstSeen: conflict.FirstSeen, LastSeen: conflict.LastSeen,
			Count: conflict.Count, Active: conflict.Active,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].LastSeen.After(result[j].LastSeen) })
	return result
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
	return supervisor.SetPeriodicScanEnabled(enabled)
}

func (a *GUIApp) SetNickname(macAddress, nickname string) error {
	supervisor, err := a.activeSupervisor()
	if err != nil {
		return err
	}
	mac, err := net.ParseMAC(macAddress)
	if err != nil {
		return err
	}
	current := supervisor.Current()
	if current == nil {
		return errors.New("runtime is not ready")
	}
	if nickname == "" {
		return current.RemoveNickname(mac)
	}
	return current.SetNickname(mac, nickname)
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
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-supervisor.Events():
			runtime.EventsEmit(a.ctx, "network:event", map[string]any{"kind": int(event.Kind), "at": event.At})
		}
	}
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
	return DeviceDTO{IP: value.IP.String(), MAC: value.MAC, Name: value.Name, Vendor: value.Vendor, Role: roles[value.Role], FirstSeen: value.FirstSeen, LastSeen: value.LastSeen, Online: value.Online}
}
