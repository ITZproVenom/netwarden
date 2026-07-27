package capture

import (
	"errors"
	"fmt"
)

var (
	ErrPermissionDenied   = errors.New("packet capture permission denied")
	ErrRuntimeUnavailable = errors.New("packet capture runtime unavailable")
	ErrInterfaceMissing   = errors.New("capture interface unavailable")
)

type OperationError struct {
	Operation string
	Kind      error
	Err       error
}

func (e *OperationError) Error() string {
	return fmt.Sprintf("%s: %v: %v", e.Operation, e.Kind, e.Err)
}

func (e *OperationError) Unwrap() []error { return []error{e.Kind, e.Err} }

func NewOperationError(operation string, kind, err error) error {
	return &OperationError{Operation: operation, Kind: kind, Err: err}
}
