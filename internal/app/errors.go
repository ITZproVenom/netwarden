package app

import (
	"errors"
	"fmt"
)

var ErrNetworkChanged = errors.New("default network route changed")

type Stage string

const (
	StageConfiguration   Stage = "configuration"
	StageGatewayRoute    Stage = "gateway_route"
	StageCaptureOpen     Stage = "capture_open"
	StageGatewayIdentity Stage = "gateway_identity"
	StageCapture         Stage = "capture"
	StageDiscovery       Stage = "discovery"
	StageNetworkChange   Stage = "network_change"
	StageShutdown        Stage = "shutdown"
	StagePersistence     Stage = "persistence"
)

type Error struct {
	Stage Stage
	Err   error
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %v", e.Stage, e.Err) }
func (e *Error) Unwrap() error { return e.Err }

func stageError(stage Stage, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Stage: stage, Err: err}
}
