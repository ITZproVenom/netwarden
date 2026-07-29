//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	coreapp "github.com/amdzy/NetWarden/internal/app"
	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/capture/helperclient"
)

func configureCapture(ctx context.Context, dependencies *coreapp.Dependencies) error {
	if os.Geteuid() == 0 {
		return nil
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate NetWarden executable: %w", err)
	}
	pkexec, err := exec.LookPath("pkexec")
	if err != nil {
		return errors.New("PolicyKit pkexec is required to request packet-capture privileges")
	}
	dependencies.Open = func(interfaceName string) (capture.Driver, error) {
		return helperclient.Open(ctx, pkexec, executable, "capture-helper", "--interface", interfaceName)
	}
	return nil
}

func platformAskpass() error {
	return errors.New("askpass mode is only supported on macOS")
}
