import type {
  Activity,
  AppInfo,
  Bootstrap,
  BandwidthLimit,
  BandwidthTraffic,
  Conflict,
  ControlAudit,
  Device,
  HistorySummary,
	IPv6Network,
  MonitoringSettings,
  NotificationSettings,
  RuntimeStatus,
} from "./types"

const backend = () => {
  const app = window.go?.main?.GUIApp
  if (!app) throw new Error("Wails backend is unavailable in this browser session.")
  return app
}

export const wailsClient = {
  appInfo: () => backend().AppInfo() as Promise<AppInfo>,
  bootstrap: () => backend().Bootstrap() as Promise<Bootstrap>,
  status: () => backend().Status() as Promise<RuntimeStatus>,
  ipv6Network: () => backend().IPv6Network() as Promise<IPv6Network>,
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
  notificationSettings: () => backend().NotificationSettings() as Promise<NotificationSettings>,
  setNotificationSettings: (settings: NotificationSettings) =>
    backend().SetNotificationSettings(settings) as Promise<void>,
  controlAudit: (limit = 250) => backend().ControlAudit(limit) as Promise<ControlAudit[]>,
  disconnectDevice: (ip: string, mac: string) => backend().DisconnectDevice(ip, mac) as Promise<void>,
  disconnectAllDevices: () => backend().DisconnectAllDevices() as Promise<void>,
  disconnectSelectedDevices: (targets: Array<{ ip: string; mac: string }>) =>
    backend().DisconnectSelectedDevices(targets) as Promise<void>,
  startContinuousControl: (ip: string, mac: string) => backend().StartContinuousControl(ip, mac) as Promise<void>,
  restoreControl: (ip: string, mac: string) => backend().RestoreControl(ip, mac) as Promise<void>,
  restoreAllControls: () => backend().RestoreAllControls() as Promise<void>,
  stopContinuousControl: (ip: string, mac: string) => backend().StopContinuousControl(ip, mac) as Promise<void>,
  bandwidthLimits: () => backend().BandwidthLimits() as Promise<BandwidthLimit[]>,
  setBandwidthLimit: (ip: string, mac: string, downloadBitsPerSecond: number, uploadBitsPerSecond: number) =>
    backend().SetBandwidthLimit(ip, mac, downloadBitsPerSecond, uploadBitsPerSecond, 0) as Promise<void>,
  removeBandwidthLimit: (mac: string) => backend().RemoveBandwidthLimit(mac) as Promise<void>,
  clearBandwidthLimits: () => backend().ClearBandwidthLimits() as Promise<void>,
  startBandwidthMonitor: (ip: string, mac: string) => backend().StartBandwidthMonitor(ip, mac) as Promise<void>,
  stopBandwidthMonitor: (mac: string) => backend().StopBandwidthMonitor(mac) as Promise<void>,
  bandwidthTraffic: () => backend().BandwidthTraffic() as Promise<BandwidthTraffic[]>,
  openConfigurationDirectory: () => backend().OpenConfigurationDirectory() as Promise<void>,
  openLogDirectory: () => backend().OpenLogDirectory() as Promise<void>,
}
