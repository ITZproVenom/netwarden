import { useEffect, useState, type ReactNode } from "react"
import { Clock3 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { useRuntimeStatus } from "@/features/monitoring/monitoring.queries"
import type { MonitoringSettings } from "@/lib/wails/types"
import { useMonitoringSettings, useSetMonitoringSettings } from "./settings.queries"
import { useUnsavedChanges } from "@/app/unsaved-changes"
import { validateRange } from "./validation"

const defaults: MonitoringSettings = {
  scanIntervalSeconds: 10,
  offlineAfterSeconds: 60,
  historyRetentionDays: 90,
  autoStart: false,
  periodicDiscovery: true,
}

export function MonitoringSettingsCard() {
  const { data } = useMonitoringSettings()
  const { data: status } = useRuntimeStatus()
  const mutation = useSetMonitoringSettings()
  const [form, setForm] = useState(defaults)
  useEffect(() => {
    if (data) setForm(data)
  }, [data])
  const running = Boolean(status?.Running || status?.Rebuilding)
  const changed = Boolean(data && JSON.stringify(form) !== JSON.stringify(data))
  useUnsavedChanges("monitoring-settings", changed)
  const errors = {
    scanIntervalSeconds: validateRange(form.scanIntervalSeconds, 5, 3600, "Scan interval"),
    offlineAfterSeconds: validateRange(form.offlineAfterSeconds, 30, 86400, "Offline timeout"),
    historyRetentionDays: validateRange(form.historyRetentionDays, 1, 3650, "History retention"),
  }
  const valid = !Object.values(errors).some(Boolean)
  const numberField = (key: "scanIntervalSeconds" | "offlineAfterSeconds" | "historyRetentionDays", value: string) =>
    setForm((current) => ({ ...current, [key]: Number(value) }))

  return (
    <Card className="bg-card/60">
      <CardHeader className="border-b">
        <div className="flex items-center gap-3">
          <span className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary">
            <Clock3 className="size-4" />
          </span>
          <div>
            <CardTitle>Monitoring behavior</CardTitle>
            <CardDescription>Control discovery cadence, liveness, retention, and startup</CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="grid grid-cols-2 gap-x-16 gap-y-7 py-8">
        <Setting
          label="Scan interval"
          description="Seconds between periodic discovery scans."
          error={errors.scanIntervalSeconds}
        >
          <Input
            type="number"
            min={5}
            max={3600}
            disabled={running}
            value={form.scanIntervalSeconds}
            onChange={(event) => numberField("scanIntervalSeconds", event.target.value)}
            aria-invalid={Boolean(errors.scanIntervalSeconds)}
          />
        </Setting>
        <Setting
          label="Offline timeout"
          description="Seconds without an observation before a peer is marked offline."
          error={errors.offlineAfterSeconds}
        >
          <Input
            type="number"
            min={30}
            max={86400}
            disabled={running}
            value={form.offlineAfterSeconds}
            onChange={(event) => numberField("offlineAfterSeconds", event.target.value)}
            aria-invalid={Boolean(errors.offlineAfterSeconds)}
          />
        </Setting>
        <Setting
          label="History retention"
          description="Days to retain device and conflict history."
          error={errors.historyRetentionDays}
        >
          <Input
            type="number"
            min={1}
            max={3650}
            disabled={running}
            value={form.historyRetentionDays}
            onChange={(event) => numberField("historyRetentionDays", event.target.value)}
            aria-invalid={Boolean(errors.historyRetentionDays)}
          />
        </Setting>
        <div className="space-y-5">
          <Toggle
            label="Periodic discovery"
            description="Run discovery automatically at the configured interval."
            checked={form.periodicDiscovery}
            disabled={running}
            onChange={(checked) => setForm((current) => ({ ...current, periodicDiscovery: checked }))}
          />
          <Toggle
            label="Start automatically"
            description="Begin monitoring the saved adapter when NetWarden opens."
            checked={form.autoStart}
            disabled={running}
            onChange={(checked) => setForm((current) => ({ ...current, autoStart: checked }))}
          />
        </div>
        <div className="col-span-2 flex items-center justify-between border-t pt-5">
          <p className="text-xs text-muted-foreground">
            {running
              ? "Stop monitoring to change these settings."
              : "Changes take effect the next time monitoring starts."}
          </p>
          <div className="flex gap-2">
            <Button variant="outline" disabled={!changed || mutation.isPending} onClick={() => data && setForm(data)}>
              Reset
            </Button>
            <Button
              disabled={running || !changed || !valid || mutation.isPending}
              onClick={() => mutation.mutate(form)}
            >
              Save monitoring settings
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function Setting({
  label,
  description,
  error,
  children,
}: {
  label: string
  description: string
  error?: string
  children: ReactNode
}) {
  return (
    <div className="space-y-2">
      <Label>{label}</Label>
      <p className="text-xs text-muted-foreground">{description}</p>
      {children}
      {error && (
        <p className="text-xs text-destructive" role="alert">
          {error}
        </p>
      )}
    </div>
  )
}

function Toggle({
  label,
  description,
  checked,
  disabled,
  onChange,
}: {
  label: string
  description: string
  checked: boolean
  disabled: boolean
  onChange: (checked: boolean) => void
}) {
  return (
    <div className="flex items-center justify-between gap-5">
      <div>
        <Label>{label}</Label>
        <p className="mt-1 text-xs text-muted-foreground">{description}</p>
      </div>
      <Switch checked={checked} disabled={disabled} onCheckedChange={onChange} />
    </div>
  )
}
