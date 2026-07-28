export type Adapter = { name: string; systemName: string; description: string; mac: string; prefixes: string[] }
export type Bootstrap = { interfaces: Adapter[]; selectedInterface: string; gatewayMAC: string }
export type Device = { ip: string; mac: string; name: string; vendor: string; role: string; firstSeen: string; lastSeen: string; online: boolean }
export type Conflict = { gatewayIP: string; claimedMAC: string; firstSeen: string; lastSeen: string; count: number; active: boolean }
export type RuntimeStatus = { Running: boolean; Scanning: boolean; PeriodicScanEnabled: boolean; DeviceCount: number; Rebuilding: boolean; ConflictCount: number }
