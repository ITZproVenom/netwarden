//go:build !darwin

package main

import (
	"context"
	"errors"

	coreapp "github.com/amdzy/NetWarden/internal/app"
)

func configureCapture(context.Context, *coreapp.Dependencies) error { return nil }

func platformAskpass() error {
	return errors.New("GUI administrator prompt is not supported on this platform")
}
