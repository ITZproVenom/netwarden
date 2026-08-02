import { createContext, useContext, type ReactNode } from "react"
import { useStoredState } from "@/lib/preferences"

export type RateUnit = "megabytes" | "megabits"

const RateUnitContext = createContext<{
  rateUnit: RateUnit
  setRateUnit: (unit: RateUnit) => void
} | null>(null)

export function MeasurementProvider({ children }: { children: ReactNode }) {
  const [rateUnit, setRateUnit] = useStoredState<RateUnit>("netwarden-rate-unit", "megabytes")
  return <RateUnitContext.Provider value={{ rateUnit, setRateUnit }}>{children}</RateUnitContext.Provider>
}

// The provider and its hook intentionally live together as one preference boundary.
// eslint-disable-next-line react-refresh/only-export-components
export function useRateUnit() {
  const value = useContext(RateUnitContext)
  if (!value) throw new Error("useRateUnit must be used inside MeasurementProvider")
  return value
}
