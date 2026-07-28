package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"time"

	coreapp "github.com/amdzy/NetWarden/internal/app"
	"github.com/amdzy/NetWarden/internal/controlaudit"
)

type ControlAuditDTO struct {
	At        time.Time `json:"at"`
	Operation string    `json:"operation"`
	Outcome   string    `json:"outcome"`
	Targets   []string  `json:"targets"`
}

func (a *GUIApp) DisconnectDevice(ipText, macText string) error {
	commands, target, ctx, cancel, err := a.controlCommand(ipText, macText)
	if err != nil {
		return err
	}
	defer cancel()
	err = commands.Disconnect(ctx, target)
	a.logControlResult("disconnect", ipText, macText, err)
	return err
}

func (a *GUIApp) DisconnectAllDevices() error {
	commands, ctx, cancel, err := a.controlCommands()
	if err != nil {
		return err
	}
	defer cancel()
	err = commands.DisconnectAll(ctx)
	a.logControlResult("disconnect_all", "", "", err)
	return err
}

func (a *GUIApp) StartContinuousControl(ipText, macText string) error {
	commands, target, ctx, cancel, err := a.controlCommand(ipText, macText)
	if err != nil {
		return err
	}
	defer cancel()
	err = commands.StartContinuous(ctx, target)
	a.logControlResult("continuous", ipText, macText, err)
	return err
}

func (a *GUIApp) RestoreControl(ipText, macText string) error {
	commands, target, ctx, cancel, err := a.controlCommand(ipText, macText)
	if err != nil {
		return err
	}
	defer cancel()
	err = commands.Restore(ctx, target)
	a.logControlResult("restore", ipText, macText, err)
	return err
}

func (a *GUIApp) RestoreAllControls() error {
	commands, ctx, cancel, err := a.controlCommands()
	if err != nil {
		return err
	}
	defer cancel()
	err = commands.RestoreAll(ctx)
	a.logControlResult("restore_all", "", "", err)
	return err
}

func (a *GUIApp) StopContinuousControl(ipText, macText string) error {
	commands, target, ctx, cancel, err := a.controlCommand(ipText, macText)
	if err != nil {
		return err
	}
	defer cancel()
	err = commands.StopContinuous(ctx, target)
	a.logControlResult("stop_continuous", ipText, macText, err)
	return err
}

func (a *GUIApp) logControlResult(operation, ip, mac string, err error) {
	level, message := slog.LevelInfo, "control action completed"
	if err != nil {
		level, message = slog.LevelError, "control action failed"
	}
	a.log(level, message, "component", "control", "operation", operation, "ip", ip, "mac", mac, "error", err)
}

func (a *GUIApp) controlCommand(ipText, macText string) (*coreapp.ControlCommands, coreapp.ControlTarget, context.Context, context.CancelFunc, error) {
	commands, ctx, cancel, err := a.controlCommands()
	if err != nil {
		return nil, coreapp.ControlTarget{}, nil, func() {}, err
	}
	ip, err := netip.ParseAddr(ipText)
	if err != nil {
		cancel()
		return nil, coreapp.ControlTarget{}, nil, func() {}, fmt.Errorf("parse target IP: %w", err)
	}
	mac, err := net.ParseMAC(macText)
	if err != nil {
		cancel()
		return nil, coreapp.ControlTarget{}, nil, func() {}, fmt.Errorf("parse target MAC: %w", err)
	}
	return commands, coreapp.ControlTarget{IP: ip, MAC: mac}, ctx, cancel, nil
}

func (a *GUIApp) controlCommands() (*coreapp.ControlCommands, context.Context, context.CancelFunc, error) {
	supervisor, err := a.activeSupervisor()
	if err != nil {
		return nil, nil, func() {}, err
	}
	runtime := supervisor.Current()
	if runtime == nil {
		return nil, nil, func() {}, errors.New("runtime is not ready")
	}
	store, _, err := loadSettings()
	if err != nil {
		return nil, nil, func() {}, err
	}
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	return runtime.ControlCommands(controlaudit.NewStore(store.Path()+".control-audit.jsonl"), nil), ctx, cancel, nil
}

func (a *GUIApp) ControlAudit() ([]ControlAuditDTO, error) {
	store, _, err := loadSettings()
	if err != nil {
		return nil, err
	}
	events, err := controlaudit.NewStore(store.Path() + ".control-audit.jsonl").Query(controlaudit.Query{})
	if err != nil {
		return nil, err
	}
	result := make([]ControlAuditDTO, 0, len(events))
	for _, event := range events {
		item := ControlAuditDTO{At: event.At, Operation: string(event.Operation), Outcome: event.Outcome}
		for _, target := range event.Targets {
			item.Targets = append(item.Targets, target.IP.String()+" · "+target.MAC.String())
		}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].At.After(result[j].At) })
	return result, nil
}
