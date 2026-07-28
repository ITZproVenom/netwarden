import type { ReactNode } from "react"
import { LaptopMinimal, Radar, Settings, ShieldCheck } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { useRuntimeStatus } from "@/features/monitoring/monitoring.queries"
import { cn } from "@/lib/utils"

export type AppView = "devices" | "integrity" | "settings"

const navigation: Array<{ value: AppView; label: string; icon: typeof LaptopMinimal }> = [
  { value: "devices", label: "Devices", icon: LaptopMinimal },
  { value: "integrity", label: "Integrity", icon: ShieldCheck },
  { value: "settings", label: "Settings", icon: Settings },
]

export function AppShell({ view, onViewChange, children }: { view: AppView; onViewChange: (view: AppView) => void; children: ReactNode }) {
  const { data: status } = useRuntimeStatus()
  const running = Boolean(status?.Running || status?.Rebuilding)

  return (
    <main className="mx-auto min-h-screen max-w-[1440px] px-6 lg:px-10">
      <header className="grid h-20 grid-cols-[1fr_auto_1fr] items-center border-b border-border/70">
        <div className="flex items-center gap-3">
          <span className="grid size-9 place-items-center rounded-xl bg-primary text-sm font-bold text-primary-foreground shadow-[0_0_24px_color-mix(in_oklch,var(--primary),transparent_65%)]">N</span>
          <div><h1 className="text-sm font-semibold">NetWarden</h1><p className="text-[10px] text-muted-foreground">Local network visibility</p></div>
        </div>
        <nav className="flex rounded-xl border border-border/60 bg-card/70 p-1">
          {navigation.map(item => <Button key={item.value} variant="ghost" size="sm" onClick={() => onViewChange(item.value)} className={cn("text-muted-foreground", view === item.value && "bg-accent text-foreground")}><item.icon />{item.label}{item.value === "integrity" && status?.ConflictCount ? <Badge variant="destructive" className="ml-1 h-4 min-w-4 px-1 text-[9px]">{status.ConflictCount}</Badge> : null}</Button>)}
        </nav>
        <div className="flex justify-end"><Badge variant="outline" className={cn("gap-2 rounded-full px-3 py-1.5 text-muted-foreground", running && "border-primary/30 text-primary")}><Radar className={cn("size-3", running && "animate-pulse")} />{running ? "Monitoring" : "Stopped"}</Badge></div>
      </header>
      {children}
      <footer className="flex justify-between py-5 text-[10px] text-muted-foreground"><span>NetWarden runs locally. Network data stays on this device.</span></footer>
    </main>
  )
}
