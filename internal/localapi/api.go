// Package localapi exposes a token-authenticated loopback control plane for a running monitor.
package localapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/amdzy/NetWarden/internal/app"
)

type Handlers struct {
	Status   func() app.Status
	Refresh  func(context.Context) error
	Periodic func(bool) error
}

type State struct {
	Address string `json:"address"`
	Token   string `json:"token"`
	PID     int    `json:"pid"`
}

type Server struct {
	statePath string
	state     State
	server    *http.Server
	listener  net.Listener
}

func Start(statePath string, handlers Handlers) (*Server, error) {
	if handlers.Status == nil || handlers.Refresh == nil || handlers.Periodic == nil {
		return nil, errors.New("local API handlers are incomplete")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		listener.Close()
		return nil, err
	}
	state := State{Address: "http://" + listener.Addr().String(), Token: hex.EncodeToString(secret), PID: os.Getpid()}
	mux := http.NewServeMux()
	authorized := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+state.Token {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("GET /status", authorized(func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(handlers.Status()) }))
	mux.HandleFunc("POST /refresh", authorized(func(w http.ResponseWriter, r *http.Request) {
		if err := handlers.Refresh(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("POST /scan/pause", authorized(func(w http.ResponseWriter, _ *http.Request) {
		if err := handlers.Periodic(false); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	mux.HandleFunc("POST /scan/resume", authorized(func(w http.ResponseWriter, _ *http.Request) {
		if err := handlers.Periodic(true); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server := &Server{statePath: statePath, state: state, listener: listener, server: &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}}
	if err := writeState(statePath, state); err != nil {
		listener.Close()
		return nil, err
	}
	go func() { _ = server.server.Serve(listener) }()
	return server, nil
}

func (s *Server) Close(ctx context.Context) error {
	err := s.server.Shutdown(ctx)
	removeErr := os.Remove(s.statePath)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	return errors.Join(err, removeErr)
}

func Call(ctx context.Context, statePath, method, endpoint string, output any) error {
	data, err := os.ReadFile(statePath)
	if err != nil {
		return fmt.Errorf("read monitor state: %w", err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode monitor state: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, method, state.Address+endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+state.Token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("contact monitor: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 {
		return fmt.Errorf("monitor returned %s", response.Status)
	}
	if output != nil {
		return json.NewDecoder(response.Body).Decode(output)
	}
	return nil
}

func writeState(path string, state State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".runtime-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if err := json.NewEncoder(temporary).Encode(state); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return replaceFile(temporaryPath, path)
}
