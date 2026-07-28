import type { Bootstrap, Conflict, Device, RuntimeStatus } from "./types"

const backend = () => window.go.main.GUIApp

export const wailsClient = {
  bootstrap: () => backend().Bootstrap() as Promise<Bootstrap>,
  status: () => backend().Status() as Promise<RuntimeStatus>,
  devices: () => backend().Devices() as Promise<Device[]>,
  conflicts: () => backend().Conflicts() as Promise<Conflict[]>,
  startMonitoring: (interfaceName: string) => backend().StartMonitoring(interfaceName) as Promise<void>,
  stopMonitoring: () => backend().StopMonitoring() as Promise<void>,
  scanNow: () => backend().ScanNow() as Promise<void>,
  setPeriodicScanEnabled: (enabled: boolean) => backend().SetPeriodicScanEnabled(enabled) as Promise<void>,
  setNickname: (mac: string, nickname: string) => backend().SetNickname(mac, nickname) as Promise<void>,
  setGatewayMAC: (mac: string) => backend().SetGatewayMAC(mac) as Promise<string>,
}
