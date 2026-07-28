//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

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
	dependencies.Open = func(interfaceName string) (driver capture.Driver, err error) {
		return helperclient.OpenWithEnv(ctx, "/usr/bin/sudo", map[string]string{
			askpassEnvironment:     "1",
			"SUDO_ASKPASS":         executable,
			"SUDO_ASKPASS_REQUIRE": "force",
		}, "-A", "--", executable, "capture-helper", "--interface", interfaceName)
	}
	return nil
}

func platformAskpass() error {
	const script = `text returned of (display dialog "NetWarden needs administrator access to capture ARP traffic." default answer "" with hidden answer buttons {"Cancel", "Continue"} default button "Continue" with title "NetWarden")`
	output, err := exec.Command("/usr/bin/osascript", "-e", script).Output()
	if err != nil {
		return errors.New("administrator authentication was cancelled")
	}
	_, err = fmt.Fprint(os.Stdout, strings.TrimSuffix(string(output), "\n"))
	return err
}
