package app

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/amdzy/NetWarden/internal/control"
	"github.com/amdzy/NetWarden/internal/device"
)

type DeviceIsolationBackend interface {
	SetDeviceIsolation(context.Context, []netip.Addr, net.HardwareAddr, bool) error
	RestoreDevice(context.Context, []netip.Addr, net.HardwareAddr) error
}

type isolationDeviceSource interface {
	Get(string) (device.Device, bool)
}

type deviceIsolationController struct {
	backend    DeviceIsolationBackend
	devices    isolationDeviceSource
	mu         sync.Mutex
	active     map[string][]netip.Addr
	continuous bool
}

func newDeviceIsolationController(backend DeviceIsolationBackend, devices isolationDeviceSource, continuous bool) *deviceIsolationController {
	return &deviceIsolationController{backend: backend, devices: devices, active: make(map[string][]netip.Addr), continuous: continuous}
}

func (c *deviceIsolationController) Isolate(ctx context.Context, target control.Endpoint) error {
	addresses, err := c.addresses(target.MAC)
	if err != nil {
		return err
	}
	if err := c.backend.SetDeviceIsolation(ctx, addresses, target.MAC, c.continuous); err != nil {
		return err
	}
	c.mu.Lock()
	c.active[target.MAC.String()] = append([]netip.Addr(nil), addresses...)
	c.mu.Unlock()
	return nil
}

func (c *deviceIsolationController) Restore(ctx context.Context, target control.Endpoint) error {
	c.mu.Lock()
	addresses := append([]netip.Addr(nil), c.active[target.MAC.String()]...)
	c.mu.Unlock()
	if len(addresses) == 0 {
		var err error
		addresses, err = c.addresses(target.MAC)
		if err != nil {
			return err
		}
	}
	if err := c.backend.RestoreDevice(ctx, addresses, target.MAC); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.active, target.MAC.String())
	c.mu.Unlock()
	return nil
}

func (c *deviceIsolationController) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (c *deviceIsolationController) Reconcile(ctx context.Context, current device.Device) error {
	mac, err := net.ParseMAC(current.MAC)
	if err != nil {
		return err
	}
	c.mu.Lock()
	_, active := c.active[mac.String()]
	c.mu.Unlock()
	if !active {
		return nil
	}
	addresses := eligibleIsolationAddresses(current.Addresses)
	if len(addresses) == 0 {
		return errors.New("isolated device has no eligible addresses")
	}
	if err := c.backend.SetDeviceIsolation(ctx, addresses, mac, c.continuous); err != nil {
		return err
	}
	c.mu.Lock()
	c.active[mac.String()] = append([]netip.Addr(nil), addresses...)
	c.mu.Unlock()
	return nil
}

func (c *deviceIsolationController) addresses(mac net.HardwareAddr) ([]netip.Addr, error) {
	if c.devices == nil {
		return nil, ErrControlRegistryUnavailable
	}
	current, ok := c.devices.Get(mac.String())
	if !ok {
		return nil, errors.New("isolation target was not found in the device registry")
	}
	addresses := eligibleIsolationAddresses(current.Addresses)
	if len(addresses) == 0 && current.IP.IsValid() {
		addresses = eligibleIsolationAddresses([]netip.Addr{current.IP})
	}
	if len(addresses) == 0 {
		return nil, errors.New("isolation target has no eligible addresses")
	}
	return addresses, nil
}

func eligibleIsolationAddresses(addresses []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{})
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
			continue
		}
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, address)
	}
	return result
}
