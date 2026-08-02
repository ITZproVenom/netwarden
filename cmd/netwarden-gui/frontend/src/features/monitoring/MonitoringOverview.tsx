import { useEffect, useState } from "react"
import { Activity, CircleStop, Play, RefreshCw, Users } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { QueryError } from "@/components/QueryError"
import { Switch } from "@/components/ui/switch"
import { useDevices } from "@/features/devices/devices.queries"
import { wailsClient } from "@/lib/wails/client"
import { useBootstrap, useRuntimeAction, useRuntimeStatus } from "./monitoring.queries"

export function MonitoringOverview() {
  const { data: bootstrap, error: bootstrapError, refetch: retryBootstrap } = useBootstrap()
  const { data: status } = useRuntimeStatus()
  const { data: devices = [] } = useDevices()
  const [selected, setSelected] = useState("")
  useEffect(() => {
    if (bootstrap && !selected) setSelected(bootstrap.selectedInterface || bootstrap.interfaces[0]?.name || "")
  }, [bootstrap, selected])
  const running = Boolean(status?.Running || status?.Rebuilding)
  const start = useRuntimeAction((name: string) => wailsClient.startMonitoring(name), "Monitoring started")
  const stop = useRuntimeAction(() => wailsClient.stopMonitoring(), "Monitoring stopped")
  const scan = useRuntimeAction(() => wailsClient.scanNow(), "Scan started")
  const periodic = useRuntimeAction(
    (enabled: boolean) => wailsClient.setPeriodicScanEnabled(enabled),
    "Periodic discovery updated",
  )
  const stats = [
    { label: "Known devices", value: devices.length, icon: Users },
    { label: "Online now", value: devices.filter((device) => device.online).length, icon: Activity },
    { label: "Current scan", value: status?.Scanning ? "Running" : "Idle", icon: RefreshCw },
    {
      label: "Gateway alerts",
      value: (status?.ConflictCount || 0) + (status?.IPv6RouterConflicts || 0) || "Clear",
      icon: Activity,
    },
  ]

  return (
    <section className="py-7 sm:py-9">
      {bootstrapError && (
        <div className="mb-5">
          <QueryError
            error={bootstrapError}
            retry={() => void retryBootstrap()}
            title="Could not load network adapters"
          />
        </div>
      )}
      <div className="mb-8 flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between lg:gap-8">
        <div>
          <p className="mb-2 text-[10px] font-semibold tracking-[.18em] text-primary uppercase">Network overview</p>
          <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">Know what’s on your network.</h2>
          <p className="mt-2 text-sm text-muted-foreground">
            Discover devices and monitor gateway security from one local dashboard.
          </p>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row">
          <NativeSelect
            value={selected}
            onChange={(event) => setSelected(event.target.value)}
            disabled={running || Boolean(bootstrapError)}
            className="w-full sm:w-64"
          >
            <NativeSelectOption value="">Select an adapter</NativeSelectOption>
            {bootstrap?.interfaces.map((adapter) => (
              <NativeSelectOption key={adapter.name} value={adapter.name}>
                {adapter.systemName || adapter.name} · {adapter.prefixes.join(", ")}
              </NativeSelectOption>
            ))}
          </NativeSelect>
          <Button
            variant={running ? "destructive" : "default"}
            disabled={!selected || start.isPending || stop.isPending}
            onClick={() => (running ? stop.mutate() : start.mutate(selected))}
          >
            {running ? <CircleStop /> : <Play />}
            {running ? "Stop monitoring" : "Start monitoring"}
          </Button>
        </div>
      </div>
      <div className="grid grid-cols-2 overflow-hidden rounded-xl border bg-card/50 lg:grid-cols-4">
        {stats.map(({ label, value, icon: Icon }) => (
          <Card
            key={label}
            className="rounded-none border-0 border-r border-b bg-transparent shadow-none last:border-r-0 lg:border-b-0"
          >
            <CardContent>
              <p className="text-xs text-muted-foreground">{label}</p>
              <div className="mt-2 flex items-center justify-between">
                <strong className="text-xl">{value}</strong>
                <Icon className="size-4 text-primary" />
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
      {running && status?.IPv6Available && (
        <p className="mt-3 text-xs text-muted-foreground">
          IPv6 {status.IPv6RouterIP ? `via ${status.IPv6RouterIP} · ${status.IPv6PrefixCount} advertised prefix${status.IPv6PrefixCount === 1 ? "" : "es"}` : "enabled · waiting for a Router Advertisement"}
        </p>
      )}
      <div className="mt-3 flex flex-wrap justify-end gap-5">
        <Button variant="outline" size="sm" disabled={!running || status?.Scanning} onClick={() => scan.mutate()}>
          <RefreshCw className={status?.Scanning ? "animate-spin" : ""} />
          Scan now
        </Button>
        <div className="flex items-center gap-2">
          <Switch
            id="periodic"
            checked={Boolean(status?.PeriodicScanEnabled)}
            disabled={!running}
            onCheckedChange={(enabled) => periodic.mutate(enabled)}
          />
          <Label htmlFor="periodic" className="text-xs text-muted-foreground">
            Periodic discovery
          </Label>
        </div>
      </div>
    </section>
  )
}
