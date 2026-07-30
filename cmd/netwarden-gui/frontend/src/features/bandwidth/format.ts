import type { BandwidthLimit } from "@/lib/wails/types"

export const displayMbps = (bitsPerSecond: number) =>
  (bitsPerSecond / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: 2 })

export function bandwidthSummary(limit?: BandwidthLimit) {
  if (!limit) return "—"
  const download = limit.downloadBitsPerSecond ? displayMbps(limit.downloadBitsPerSecond) : "∞"
  const upload = limit.uploadBitsPerSecond ? displayMbps(limit.uploadBitsPerSecond) : "∞"
  return `↓ ${download} · ↑ ${upload} Mbps`
}
