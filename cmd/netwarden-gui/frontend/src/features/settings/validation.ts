export function validateRange(value: number, minimum: number, maximum: number, label: string) {
  if (!Number.isFinite(value) || !Number.isInteger(value)) return `${label} must be a whole number.`
  if (value < minimum || value > maximum) return `${label} must be between ${minimum} and ${maximum}.`
  return undefined
}

export function validateGatewayMAC(value: string) {
  const trimmed = value.trim()
  if (!trimmed) return undefined
  if (!/^([0-9a-fA-F]{2})([:-][0-9a-fA-F]{2}){5}$/.test(trimmed))
    return "Enter six hexadecimal pairs separated by colons or hyphens."
  return undefined
}
