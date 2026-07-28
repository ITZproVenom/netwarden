package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sort"
	"time"

	coreapp "github.com/amdzy/NetWarden/internal/app"
	"github.com/amdzy/NetWarden/internal/control"
	"github.com/amdzy/NetWarden/internal/controlaudit"
)

type ControlPreparationDTO struct {
	Operation string `json:"operation"`
	Targets   int    `json:"targets"`
	Prepared  bool   `json:"prepared"`
	Message   string `json:"message"`
}

type ControlAuditDTO struct {
	At        time.Time `json:"at"`
	Operation string    `json:"operation"`
	Outcome   string    `json:"outcome"`
	Targets   []string  `json:"targets"`
}

func (a *GUIApp) PrepareControl(operation, ipText, macText string) (ControlPreparationDTO, error) {
	supervisor, err := a.activeSupervisor()
	if err != nil {
		return ControlPreparationDTO{}, err
	}
	runtime := supervisor.Current()
	if runtime == nil {
		return ControlPreparationDTO{}, errors.New("runtime is not ready")
	}
	store, _, err := loadSettings()
	if err != nil {
		return ControlPreparationDTO{}, err
	}
	auditStore := controlaudit.NewStore(store.Path() + ".control-audit.jsonl")
	commands := runtime.ControlCommands(auditStore, preparedControllerFactory{})
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
	defer cancel()
	target := coreapp.ControlTarget{}
	if operation != string(coreapp.ControlDisconnectAll) {
		ip, parseErr := netip.ParseAddr(ipText)
		if parseErr != nil {
			return ControlPreparationDTO{}, parseErr
		}
		mac, parseErr := net.ParseMAC(macText)
		if parseErr != nil {
			return ControlPreparationDTO{}, parseErr
		}
		target = coreapp.ControlTarget{IP: ip, MAC: mac}
	}
	var commandErr error
	switch coreapp.ControlOperation(operation) {
	case coreapp.ControlDisconnect:
		commandErr = commands.Disconnect(ctx, target)
	case coreapp.ControlDisconnectAll:
		commandErr = commands.DisconnectAll(ctx)
	case coreapp.ControlContinuous:
		commandErr = commands.StartContinuous(ctx, target)
	default:
		return ControlPreparationDTO{}, errors.New("unsupported control preparation")
	}
	if !errors.Is(commandErr, coreapp.ErrActiveControlNotImplemented) {
		return ControlPreparationDTO{}, commandErr
	}
	targetCount := 1
	if operation == string(coreapp.ControlDisconnectAll) {
		events, queryErr := auditStore.Query(controlaudit.Query{Operation: coreapp.ControlDisconnectAll, Outcome: "ready_not_implemented"})
		if queryErr == nil && len(events) > 0 {
			targetCount = len(events[len(events)-1].Targets)
		}
	}
	return ControlPreparationDTO{Operation: operation, Targets: targetCount, Prepared: true, Message: commandErr.Error()}, nil
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

type preparedControllerFactory struct{}

func (preparedControllerFactory) Prepare(context.Context, coreapp.ControlRequest, coreapp.ControlScope) (coreapp.ControlControllerLease, error) {
	return coreapp.ControlControllerLease{Controller: preparedController{}}, nil
}

type preparedController struct{}

func (preparedController) Restore(context.Context, control.Endpoint) error { return nil }
func (preparedController) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
