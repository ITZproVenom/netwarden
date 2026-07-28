export function formatDate(value: string) {
  if (!value) return "Never"
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value))
}
