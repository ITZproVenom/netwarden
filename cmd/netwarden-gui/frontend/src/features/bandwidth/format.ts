import type { BandwidthLimit } from "@/lib/wails/types"
import type { RateUnit } from "@/lib/measurement"

export const displayMbps = (bitsPerSecond: number) =>
  (bitsPerSecond / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: 2 })

export const displayRateValue = (bitsPerSecond: number, unit: RateUnit) =>
  (bitsPerSecond / (unit === "megabytes" ? 8_000_000 : 1_000_000)).toLocaleString(undefined, { maximumFractionDigits: 2 })

export const rateUnitLabel = (unit: RateUnit) => unit === "megabytes" ? "MB/s" : "Mbps"

export function bandwidthSummary(limit?: BandwidthLimit, unit: RateUnit = "megabytes") {
  if (!limit) return "—"
  const download = limit.downloadBitsPerSecond ? displayRateValue(limit.downloadBitsPerSecond, unit) : "∞"
  const upload = limit.uploadBitsPerSecond ? displayRateValue(limit.uploadBitsPerSecond, unit) : "∞"
  return `↓ ${download} · ↑ ${upload} ${rateUnitLabel(unit)}`
}
