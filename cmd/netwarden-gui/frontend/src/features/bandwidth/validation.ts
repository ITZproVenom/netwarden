export const maximumMbps = 100_000

export function parseMbps(value: string): number | null {
  if (value.trim() === "") return 0
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > maximumMbps) return null
  return Math.round(parsed * 1_000_000)
}

export function bandwidthValidation(download: string, upload: string): string {
  const downloadBits = parseMbps(download)
  const uploadBits = parseMbps(upload)
  if (downloadBits === null || uploadBits === null)
    return `Enter a value from 0 to ${maximumMbps.toLocaleString()} Mbps.`
  if (downloadBits === 0 && uploadBits === 0) return "Enter a download or upload limit."
  return ""
}
