export function errorMessage(error: unknown) {
  if (error instanceof Error) return error.message
  if (typeof error === "string") return error
  return "An unexpected error occurred."
}

export function isBackendUnavailable(error: unknown) {
  return errorMessage(error).includes("Wails backend is unavailable")
}
