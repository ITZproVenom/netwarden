//go:build windows

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	coreapp "github.com/amdzy/NetWarden/internal/app"
	"github.com/amdzy/NetWarden/internal/capture"
	"github.com/amdzy/NetWarden/internal/capture/helperclient"
	"golang.org/x/sys/windows"
)

func configureCapture(ctx context.Context, dependencies *coreapp.Dependencies) error {
	token, err := windows.OpenCurrentProcessToken()
	if err == nil {
		defer token.Close()
		if token.IsElevated() {
			return nil
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate NetWarden executable: %w", err)
	}
	dependencies.Open = func(interfaceName string) (capture.Driver, error) {
		return openWindowsElevatedHelper(ctx, executable, interfaceName)
	}
	return nil
}

func openWindowsElevatedHelper(ctx context.Context, executable, interfaceName string) (capture.Driver, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for capture helper: %w", err)
	}
	defer listener.Close()
	oneTimeToken, err := randomToken()
	if err != nil {
		return nil, err
	}
	arguments := joinWindowsArguments("capture-helper", "--interface", interfaceName, "--connect", listener.Addr().String(), "--token", oneTimeToken)
	verb, _ := windows.UTF16PtrFromString("runas")
	program, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return nil, err
	}
	parameters, err := windows.UTF16PtrFromString(arguments)
	if err != nil {
		return nil, err
	}
	if err := windows.ShellExecute(0, verb, program, parameters, nil, windows.SW_HIDE); err != nil {
		return nil, fmt.Errorf("request administrator access: %w", err)
	}
	connection, err := acceptAuthenticatedHelper(ctx, listener, oneTimeToken)
	if err != nil {
		return nil, err
	}
	return helperclient.OpenConnection(ctx, connection)
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("create helper authentication token: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func joinWindowsArguments(arguments ...string) string {
	escaped := make([]string, len(arguments))
	for index, argument := range arguments {
		escaped[index] = syscall.EscapeArg(argument)
	}
	return strings.Join(escaped, " ")
}

func acceptAuthenticatedHelper(ctx context.Context, listener net.Listener, expectedToken string) (net.Conn, error) {
	deadline := time.Now().Add(45 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, errors.New("elevated capture helper did not authenticate")
		}
		if deadlineListener, ok := listener.(*net.TCPListener); ok {
			_ = deadlineListener.SetDeadline(time.Now().Add(500 * time.Millisecond))
		}
		connection, err := listener.Accept()
		if err != nil {
			var networkError net.Error
			if errors.As(err, &networkError) && networkError.Timeout() {
				continue
			}
			return nil, fmt.Errorf("wait for elevated capture helper: %w", err)
		}
		_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
		providedToken, readErr := bufio.NewReader(connection).ReadString('\n')
		if readErr == nil && strings.TrimSpace(providedToken) == expectedToken {
			if _, err := connection.Write([]byte("ok\n")); err != nil {
				_ = connection.Close()
				return nil, fmt.Errorf("acknowledge elevated capture helper: %w", err)
			}
			_ = connection.SetDeadline(time.Time{})
			return connection, nil
		}
		_ = connection.Close()
	}
}

func platformAskpass() error {
	return errors.New("askpass mode is only supported on macOS")
}
