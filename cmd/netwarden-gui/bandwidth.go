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

type BandwidthTrafficDTO struct {
	MAC             string `json:"mac"`
	UploadPackets   uint64 `json:"uploadPackets"`
	UploadBytes     uint64 `json:"uploadBytes"`
	DownloadPackets uint64 `json:"downloadPackets"`
	DownloadBytes   uint64 `json:"downloadBytes"`
}

type BandwidthMonitorDTO struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

func (a *GUIApp) BandwidthMonitors() ([]BandwidthMonitorDTO, error) {
	a.mu.RLock()
	supervisor := a.supervisor
	a.mu.RUnlock()
	if supervisor == nil || supervisor.Current() == nil {
		return []BandwidthMonitorDTO{}, nil
	}
	targets := supervisor.Current().BandwidthMonitors()
	result := make([]BandwidthMonitorDTO, 0, len(targets))
	for _, target := range targets {
		result = append(result, BandwidthMonitorDTO{IP: target.IP.String(), MAC: target.MAC.String()})
	}
	return result, nil
}

type BandwidthMeasurementDTO struct {
	MAC             string                     `json:"mac"`
	UploadBytes     uint64                     `json:"uploadBytes"`
	DownloadBytes   uint64                     `json:"downloadBytes"`
	UploadBPS       uint64                     `json:"uploadBPS"`
	DownloadBPS     uint64                     `json:"downloadBPS"`
	PeakUploadBPS   uint64                     `json:"peakUploadBPS"`
	PeakUploadAt    time.Time                  `json:"peakUploadAt,omitempty"`
	PeakDownloadBPS uint64                     `json:"peakDownloadBPS"`
	PeakDownloadAt  time.Time                  `json:"peakDownloadAt,omitempty"`
	History         []BandwidthHistoryPointDTO `json:"history"`
}

type BandwidthHistoryPointDTO struct {
	At            time.Time `json:"at"`
	UploadBytes   uint64    `json:"uploadBytes"`
	DownloadBytes uint64    `json:"downloadBytes"`
	UploadBPS     uint64    `json:"uploadBPS"`
	DownloadBPS   uint64    `json:"downloadBPS"`
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

func (a *GUIApp) StartBandwidthMonitor(ipText, macText string) error {
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
	err = runtime.StartBandwidthMonitor(ctx, coreapp.ControlTarget{IP: ip, MAC: mac})
	a.logBandwidthResult("monitor_start", ipText, macText, err)
	return err
}

func (a *GUIApp) StopBandwidthMonitor(macText string) error {
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
	err = runtime.StopBandwidthMonitor(ctx, mac)
	a.logBandwidthResult("monitor_stop", "", macText, err)
	return err
}

func (a *GUIApp) BandwidthTraffic() ([]BandwidthTrafficDTO, error) {
	runtime, err := a.activeRuntime()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(a.ctx, 5*time.Second)
	defer cancel()
	traffic, err := runtime.BandwidthTraffic(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]BandwidthTrafficDTO, 0, len(traffic))
	for _, current := range traffic {
		result = append(result, BandwidthTrafficDTO{MAC: current.MAC, UploadPackets: current.UploadPackets,
			UploadBytes: current.UploadBytes, DownloadPackets: current.DownloadPackets, DownloadBytes: current.DownloadBytes})
	}
	return result, nil
}

func (a *GUIApp) BandwidthMeasurements() ([]BandwidthMeasurementDTO, error) {
	runtime, err := a.activeRuntime()
	if err != nil {
		return nil, err
	}
	measurements, err := runtime.BandwidthMeasurements()
	if err != nil {
		return nil, err
	}
	result := make([]BandwidthMeasurementDTO, 0, len(measurements))
	for _, current := range measurements {
		item := BandwidthMeasurementDTO{MAC: current.MAC, UploadBytes: current.UploadBytes, DownloadBytes: current.DownloadBytes,
			UploadBPS: current.UploadBPS, DownloadBPS: current.DownloadBPS, PeakUploadBPS: current.PeakUploadBPS,
			PeakUploadAt: current.PeakUploadAt, PeakDownloadBPS: current.PeakDownloadBPS, PeakDownloadAt: current.PeakDownloadAt,
			History: make([]BandwidthHistoryPointDTO, 0, len(current.History))}
		for _, point := range current.History {
			item.History = append(item.History, BandwidthHistoryPointDTO{At: point.At, UploadBytes: point.UploadBytes,
				DownloadBytes: point.DownloadBytes, UploadBPS: point.UploadBPS, DownloadBPS: point.DownloadBPS})
		}
		result = append(result, item)
	}
	return result, nil
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
