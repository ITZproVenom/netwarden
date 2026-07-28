import { beforeEach, describe, expect, it, vi } from "vitest"
import { wailsClient } from "./client"

describe("wailsClient", () => {
  const backend = {
    Bootstrap: vi.fn(),
    Status: vi.fn(),
    Devices: vi.fn(),
    Conflicts: vi.fn(),
    StartMonitoring: vi.fn(),
    StopMonitoring: vi.fn(),
    ScanNow: vi.fn(),
    SetPeriodicScanEnabled: vi.fn(),
    SetNickname: vi.fn(),
    SetGatewayMAC: vi.fn(),
    DisconnectAllDevices: vi.fn(),
  }

  beforeEach(() => {
    vi.clearAllMocks()
    window.go = { main: { GUIApp: backend } }
  })

  it("keeps Wails method names out of feature components", async () => {
    backend.StartMonitoring.mockResolvedValue(undefined)
    await wailsClient.startMonitoring("en0")
    expect(backend.StartMonitoring).toHaveBeenCalledWith("en0")
  })

  it("returns the canonical gateway address from the backend", async () => {
    backend.SetGatewayMAC.mockResolvedValue("00:11:22:33:44:55")
    await expect(wailsClient.setGatewayMAC("00-11-22-33-44-55")).resolves.toBe("00:11:22:33:44:55")
  })

  it("dispatches bulk disconnect to the backend", async () => {
    backend.DisconnectAllDevices.mockResolvedValue(undefined)
    await wailsClient.disconnectAllDevices()
    expect(backend.DisconnectAllDevices).toHaveBeenCalledOnce()
  })
})
