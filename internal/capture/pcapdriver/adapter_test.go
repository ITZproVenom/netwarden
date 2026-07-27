package pcapdriver

import (
	"errors"
	"testing"

	"github.com/amdzy/NetWarden/internal/capture"
)

func TestClassifyOpenError(t *testing.T) {
	tests := []struct {
		message string
		want    error
	}{
		{"permission denied", capture.ErrPermissionDenied},
		{"No such device exists", capture.ErrInterfaceMissing},
		{"libpcap unavailable", capture.ErrRuntimeUnavailable},
	}
	for _, test := range tests {
		err := classifyOpenError("en0", errors.New(test.message))
		if !errors.Is(err, test.want) {
			t.Errorf("classify %q: got %v, want %v", test.message, err, test.want)
		}
		var operation *capture.OperationError
		if !errors.As(err, &operation) || operation.Operation == "" {
			t.Errorf("classify %q did not preserve operation context: %v", test.message, err)
		}
	}
}
