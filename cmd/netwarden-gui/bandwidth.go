package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	coreapp "github.com/amdzy/NetWarden/internal/app"
	"github.com/amdzy/NetWarden/internal/shaping"
)

type BandwidthLimitDTO struct {
	IP                    string `json:"ip"`
	MAC                   string `json:"mac"`
	DownloadBitsPerSecond uint64 `json:"downloadBitsPerSecond"`
	UploadBitsPerSecond   uint64 `json:"uploadBitsPerSecond"`
	BurstBytes            int    `json:"burstBytes"`
}

func (a *GUIApp) BandwidthLimits() ([]BandwidthLimitDTO, error) {
	a.mu.RLock()
	supervisor := a.supervisor
	a.mu.RUnlock()
	if supervisor == nil || supervisor.Current() == nil {
		return []BandwidthLimitDTO{}, nil
	}
	limits := supervisor.Current().BandwidthLimits()
	result := make([]BandwidthLimitDTO, 0, len(limits))
	for _, limit := range limits {
		result = append(result, BandwidthLimitDTO{
			IP: limit.IP.String(), MAC: limit.MAC.String(),
			DownloadBitsPerSecond: limit.Policy.DownloadBitsPerSecond,
			UploadBitsPerSecond:   limit.Policy.UploadBitsPerSecond,
			BurstBytes:            limit.Policy.BurstBytes,
		})
	}
	return result, nil
}

func (a *GUIApp) SetBandwidthLimit(ipText, macText string, downloadBitsPerSecond, uploadBitsPerSecond uint64, burstBytes int) error {
	runtime, err := a.activeRuntime()
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(ipText)
	if err != nil {
		return fmt.Errorf("parse target IP: %w", err)
	}
	mac, err := net.ParseMAC(macText)
	if err != nil {
		return fmt.Errorf("parse target MAC: %w", err)
	}
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()
	err = runtime.SetBandwidthLimit(ctx, coreapp.ControlTarget{IP: ip, MAC: mac}, shaping.Policy{
		DownloadBitsPerSecond: downloadBitsPerSecond,
		UploadBitsPerSecond:   uploadBitsPerSecond,
		BurstBytes:            burstBytes,
	})
	a.logBandwidthResult("set", ipText, macText, err)
	return err
}

func (a *GUIApp) RemoveBandwidthLimit(macText string) error {
	runtime, err := a.activeRuntime()
	if err != nil {
		return err
	}
	mac, err := net.ParseMAC(macText)
	if err != nil {
		return fmt.Errorf("parse target MAC: %w", err)
	}
	ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()
	err = runtime.RemoveBandwidthLimit(ctx, mac)
	a.logBandwidthResult("remove", "", macText, err)
	return err
}

func (a *GUIApp) ClearBandwidthLimits() error {
	runtime, err := a.activeRuntime()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(a.ctx, 15*time.Second)
	defer cancel()
	err = runtime.ClearBandwidthLimits(ctx)
	a.logBandwidthResult("clear", "", "", err)
	return err
}

func (a *GUIApp) activeRuntime() (*coreapp.Runtime, error) {
	supervisor, err := a.activeSupervisor()
	if err != nil {
		return nil, err
	}
	runtime := supervisor.Current()
	if runtime == nil {
		return nil, fmt.Errorf("runtime is not ready")
	}
	return runtime, nil
}

func (a *GUIApp) logBandwidthResult(operation, ip, mac string, err error) {
	level, message := slog.LevelInfo, "bandwidth action completed"
	if err != nil {
		level, message = slog.LevelError, "bandwidth action failed"
	}
	a.log(level, message, "component", "bandwidth", "operation", operation, "ip", ip, "mac", mac, "error", err)
}
