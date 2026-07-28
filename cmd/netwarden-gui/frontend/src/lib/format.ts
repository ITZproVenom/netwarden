export function formatDate(value: string) {
  if (!value) return "Never"
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value))
}

export function formatRelativeDate(value: string, now = Date.now()) {
  const difference = new Date(value).getTime() - now
  if (!Number.isFinite(difference)) return "Unknown"
  const absolute = Math.abs(difference)
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ["day", 86_400_000],
    ["hour", 3_600_000],
    ["minute", 60_000],
    ["second", 1_000],
  ]
  const [unit, duration] = units.find(([, size]) => absolute >= size) || units[units.length - 1]
  return new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }).format(Math.round(difference / duration), unit)
}
