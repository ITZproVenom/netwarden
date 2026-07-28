import type { Activity, Bootstrap, Conflict, Device, HistorySummary, MonitoringSettings, RuntimeStatus } from "./types"

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
  historySummary: () => backend().HistorySummary() as Promise<HistorySummary>,
  pruneHistory: (olderThanDays: number) => backend().PruneHistory(olderThanDays) as Promise<void>,
  clearHistory: () => backend().ClearHistory() as Promise<void>,
  activity: () => backend().Activity() as Promise<Activity[]>,
  monitoringSettings: () => backend().MonitoringSettings() as Promise<MonitoringSettings>,
  setMonitoringSettings: (settings: MonitoringSettings) => backend().SetMonitoringSettings(settings) as Promise<void>,
}
