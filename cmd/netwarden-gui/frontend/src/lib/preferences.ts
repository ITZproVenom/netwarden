import { useState } from "react"

export function useStoredState<T>(key: string, fallback: T) {
  const [value, setValue] = useState<T>(() => {
    try {
      const stored = localStorage.getItem(key)
      return stored === null ? fallback : (JSON.parse(stored) as T)
    } catch {
      return fallback
    }
  })
  const update = (next: T | ((current: T) => T)) =>
    setValue((current) => {
      const resolved = typeof next === "function" ? (next as (current: T) => T)(current) : next
      try {
        localStorage.setItem(key, JSON.stringify(resolved))
      } catch {
        /* Preferences remain session-local when storage is unavailable. */
      }
      return resolved
    })
  return [value, update] as const
}
