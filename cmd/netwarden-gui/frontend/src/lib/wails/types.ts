export type Adapter = { name: string; systemName: string; description: string; mac: string; prefixes: string[] }
export type Bootstrap = { interfaces: Adapter[]; selectedInterface: string; gatewayMAC: string }
export type DeviceControlState = "" | "active" | "continuous" | "restoring" | "failed"
export type Device = {
  ip: string
  addresses: string[]
  mac: string
  name: string
  vendor: string
  type: string
  role: string
  firstSeen: string
  lastSeen: string
  online: boolean
  controlState: DeviceControlState
}
export type Conflict = {
  gatewayIP: string
  claimedMAC: string
  firstSeen: string
  lastSeen: string
  count: number
  active: boolean
}
export type RuntimeStatus = {
  Running: boolean
  Stopped: boolean
  Scanning: boolean
  PeriodicScanEnabled: boolean
  DeviceCount: number
  DroppedEvents: number
  Generation: number
  RestartCount: number
  Rebuilding: boolean
  LastRestartReason: string
  SupervisorDroppedEvents: number
  ConflictCount: number
  LastPersistenceError: string
  BandwidthAvailable: boolean
  ActiveBandwidthLimits: number
  BandwidthMonitoringAvailable: boolean
  ActiveBandwidthMonitors: number
  IPv6Available: boolean
  IPv6RouterIP: string
  IPv6RouterMAC: string
  IPv6PrefixCount: number
  IPv6RouterConflicts: number
}
export type IPv6Prefix = {
  prefix: string
  onLink: boolean
  autonomous: boolean
  validUntil: string
  preferredUntil: string
}
export type IPv6Router = { ip: string; mac: string; expiresAt: string; preference: number; prefixes: IPv6Prefix[] }
export type IPv6RouterConflict = {
  routerIP: string
  expectedMAC: string
  claimedMAC: string
  firstSeen: string
  lastSeen: string
  count: number
  active: boolean
}
export type IPv6Network = {
  localAddresses: string[]
  defaultRouter?: IPv6Router
  routers: IPv6Router[]
  conflictCount: number
  conflicts: IPv6RouterConflict[]
  trustedIdentities: Array<{ routerIP: string; mac: string }>
}
export type HistorySummary = { devices: number; conflicts: number; oldest?: string; newest?: string }
export type Activity = {
  at: string
  kind: string
  severity: "info" | "warning" | "error"
  title: string
  detail?: string
}
export type MonitoringSettings = {
  scanIntervalSeconds: number
  offlineAfterSeconds: number
  historyRetentionDays: number
  autoStart: boolean
  periodicDiscovery: boolean
}
export type NotificationSettings = {
  enabled: boolean
  newDevices: boolean
  knownDevices: boolean
  deviceOffline: boolean
  suspiciousDevices: boolean
}
export type ControlAudit = { at: string; operation: string; outcome: string; targets: string[] }
export type BandwidthLimit = {
  ip: string
  mac: string
  downloadBitsPerSecond: number
  uploadBitsPerSecond: number
  burstBytes: number
}
export type BandwidthTraffic = {
  mac: string
  uploadPackets: number
  uploadBytes: number
  downloadPackets: number
  downloadBytes: number
}
export type BandwidthMonitor = { ip: string; mac: string }
export type BandwidthHistoryPoint = {
  at: string
  uploadBytes: number
  downloadBytes: number
  uploadBPS: number
  downloadBPS: number
}
export type BandwidthMeasurement = {
  mac: string
  uploadBytes: number
  downloadBytes: number
  uploadBPS: number
  downloadBPS: number
  peakUploadBPS: number
  peakUploadAt?: string
  peakDownloadBPS: number
  peakDownloadAt?: string
  history: BandwidthHistoryPoint[]
}
export type AppInfo = { name: string; version: string; build: string }
