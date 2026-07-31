import type { ReactNode } from "react"
import { Gauge, LaptopMinimal, Logs, Radar, Settings, ShieldCheck } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { useRuntimeStatus } from "@/features/monitoring/monitoring.queries"
import { cn } from "@/lib/utils"

export type AppView = "devices" | "bandwidth" | "integrity" | "diagnostics" | "settings"

const navigation: Array<{ value: AppView; label: string; icon: typeof LaptopMinimal }> = [
  { value: "devices", label: "Devices", icon: LaptopMinimal },
  { value: "bandwidth", label: "Bandwidth", icon: Gauge },
  { value: "integrity", label: "Gateway Security", icon: ShieldCheck },
  { value: "diagnostics", label: "Diagnostics", icon: Logs },
  { value: "settings", label: "Settings", icon: Settings },
]

export function AppShell({
  view,
  onViewChange,
  children,
}: {
  view: AppView
  onViewChange: (view: AppView) => void
  children: ReactNode
}) {
  const { data: status } = useRuntimeStatus()
  const running = Boolean(status?.Running || status?.Rebuilding)

  return (
    <main className="mx-auto min-h-screen max-w-[1440px] px-3 sm:px-6 lg:px-10">
      <header className="flex min-h-20 flex-wrap items-center justify-between gap-3 border-b border-border/70 py-3 lg:grid lg:grid-cols-[1fr_auto_1fr]">
        <div className="flex items-center gap-3">
          <BrandIcon />
          <div>
            <h1 className="text-sm font-semibold">NetWarden</h1>
            <p className="text-[10px] text-muted-foreground">Local network visibility</p>
          </div>
        </div>
        <nav
          aria-label="Primary navigation"
          className="order-3 flex w-full gap-1 overflow-x-auto rounded-xl border border-border/60 bg-card/70 p-1 lg:order-none lg:w-auto"
        >
          {navigation.map((item) => (
            <Button
              key={item.value}
              variant="ghost"
              size="sm"
              aria-current={view === item.value ? "page" : undefined}
              onClick={() => onViewChange(item.value)}
              className={cn("shrink-0 text-muted-foreground", view === item.value && "bg-accent text-foreground")}
            >
              <item.icon />
              {item.label}
              {item.value === "integrity" && status?.ConflictCount ? (
                <Badge variant="destructive" className="ml-1 h-4 min-w-4 px-1 text-[9px]">
                  {status.ConflictCount}
                </Badge>
              ) : null}
            </Button>
          ))}
        </nav>
        <div className="flex justify-end">
          <Badge
            variant="outline"
            className={cn(
              "gap-2 rounded-full px-3 py-1.5 text-muted-foreground",
              running && "border-primary/30 text-primary",
            )}
          >
            <Radar className={cn("size-3", running && "animate-pulse")} />
            {running ? "Monitoring" : "Stopped"}
          </Badge>
        </div>
      </header>
      {children}
      <footer className="flex justify-between py-5 text-[10px] text-muted-foreground">
        <span>NetWarden runs locally. Network data stays on this device.</span>
      </footer>
    </main>
  )
}

function BrandIcon() {
  return (
    <svg
      viewBox="0 0 36 36"
      aria-hidden="true"
      className="size-9 shrink-0 rounded-xl shadow-[0_0_24px_color-mix(in_oklch,var(--primary),transparent_65%)]"
    >
      <defs>
        <linearGradient id="brand-background" x1="4" y1="2" x2="31" y2="34" gradientUnits="userSpaceOnUse">
          <stop stopColor="#07172f" />
          <stop offset="1" stopColor="#020817" />
        </linearGradient>
        <linearGradient id="brand-mark" x1="8" y1="6" x2="29" y2="31" gradientUnits="userSpaceOnUse">
          <stop stopColor="#2dd4bf" />
          <stop offset="1" stopColor="#14b8a6" />
        </linearGradient>
      </defs>
      <rect width="36" height="36" rx="10" fill="url(#brand-background)" />
      <path
        d="M18 5.2c3.5 2.7 7 4.3 11 5.1v7.1c0 6-3.7 10.7-11 13.5C10.7 28.1 7 23.4 7 17.4v-7.1c4-.8 7.5-2.4 11-5.1Z"
        fill="none"
        stroke="url(#brand-mark)"
        strokeWidth="2.2"
        strokeLinejoin="round"
      />
      <path d="m13.2 21.8 4.8-8 4.8 8H13.2Z" fill="none" stroke="#5eead4" strokeWidth="1.4" />
      <circle cx="18" cy="13.8" r="2" fill="#ccfbf1" />
      <circle cx="13.3" cy="21.8" r="2" fill="#2dd4bf" />
      <circle cx="22.7" cy="21.8" r="2" fill="#2dd4bf" />
    </svg>
  )
}
