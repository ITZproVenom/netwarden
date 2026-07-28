import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react"

type UnsavedChanges = { dirty: boolean; setDirty: (source: string, dirty: boolean) => void }
const UnsavedChangesContext = createContext<UnsavedChanges | null>(null)

export function UnsavedChangesProvider({ children }: { children: ReactNode }) {
  const [sources, setSources] = useState<Set<string>>(() => new Set())
  const setDirty = useCallback(
    (source: string, dirty: boolean) =>
      setSources((current) => {
        const next = new Set(current)
        if (dirty) next.add(source)
        else next.delete(source)
        return next
      }),
    [],
  )
  const value = useMemo(() => ({ dirty: sources.size > 0, setDirty }), [sources, setDirty])
  useEffect(() => {
    if (!value.dirty) return
    const warn = (event: BeforeUnloadEvent) => event.preventDefault()
    window.addEventListener("beforeunload", warn)
    return () => window.removeEventListener("beforeunload", warn)
  }, [value.dirty])
  return <UnsavedChangesContext.Provider value={value}>{children}</UnsavedChangesContext.Provider>
}

export function useUnsavedChanges(source?: string, dirty?: boolean) {
  const context = useContext(UnsavedChangesContext)
  if (!context) throw new Error("useUnsavedChanges must be used within UnsavedChangesProvider")
  const { setDirty } = context
  useEffect(() => {
    if (!source) return
    setDirty(source, Boolean(dirty))
    return () => setDirty(source, false)
  }, [setDirty, dirty, source])
  return context
}
