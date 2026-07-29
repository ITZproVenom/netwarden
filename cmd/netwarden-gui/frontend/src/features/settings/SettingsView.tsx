import { useEffect, useState } from "react"
import { Database, FolderOpen, Router, Trash2 } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { useBootstrap, useRuntimeStatus } from "@/features/monitoring/monitoring.queries"
import { formatDate } from "@/lib/format"
import { MonitoringSettingsCard } from "./MonitoringSettingsCard"
import { ApplicationPreferencesCard } from "./ApplicationPreferencesCard"
import { useClearHistory, useHistorySummary, usePruneHistory, useSetGatewayMAC } from "./settings.queries"
import { useOpenApplicationDirectory } from "./settings.queries"
import { useUnsavedChanges } from "@/app/unsaved-changes"
import { validateGatewayMAC } from "./validation"

export function SettingsView() {
  const { data: bootstrap } = useBootstrap()
  const { data: status } = useRuntimeStatus()
  const gateway = useSetGatewayMAC()
  const { data: history } = useHistorySummary()
  const prune = usePruneHistory()
  const clear = useClearHistory()
  const openConfig = useOpenApplicationDirectory("configuration")
  const openLogs = useOpenApplicationDirectory("logs")
  const [gatewayMAC, setGatewayMAC] = useState("")
  const [pruneDays, setPruneDays] = useState(90)
  useEffect(() => setGatewayMAC(bootstrap?.gatewayMAC || ""), [bootstrap?.gatewayMAC])
  const running = Boolean(status?.Running || status?.Rebuilding)
  const saved = bootstrap?.gatewayMAC || ""
  const gatewayChanged = gatewayMAC.trim().toLowerCase() !== saved.toLowerCase()
  const gatewayError = validateGatewayMAC(gatewayMAC)
  useUnsavedChanges("gateway-mac", gatewayChanged)

  return (
    <div className="settings-view space-y-5">
      <ApplicationPreferencesCard />
      <MonitoringSettingsCard />
      <Card className="bg-card/60">
        <CardHeader className="border-b">
          <CardTitle>Network identity</CardTitle>
          <CardDescription>Configure how NetWarden identifies this network</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-16 py-8">
          <div>
            <div className="flex items-center gap-3">
              <span className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary">
                <Router className="size-4" />
              </span>
              <h3 className="text-sm font-medium">Trusted gateway identity</h3>
            </div>
            <p className="mt-4 max-w-xl text-xs leading-6 text-muted-foreground">
              Pin the hardware address of your router. NetWarden reports gateway claims from any different MAC address.
              Leave this empty to learn the identity when monitoring starts.
            </p>
            {running && (
              <Alert className="mt-5">
                <AlertTitle>Monitoring is active</AlertTitle>
                <AlertDescription>Stop monitoring before changing protected settings or history.</AlertDescription>
              </Alert>
            )}
          </div>
          <div className="space-y-3">
            <Label htmlFor="gateway-mac">Gateway MAC address</Label>
            <Input
              id="gateway-mac"
              className="font-mono"
              spellCheck={false}
              placeholder="00:11:22:33:44:55"
              value={gatewayMAC}
              disabled={running}
              onChange={(event) => setGatewayMAC(event.target.value)}
              aria-invalid={Boolean(gatewayError)}
            />
            {gatewayError && (
              <p className="text-xs text-destructive" role="alert">
                {gatewayError}
              </p>
            )}
            <p className="text-xs text-muted-foreground">
              {saved ? `Pinned to ${saved}` : "Automatically learned when monitoring starts"}
            </p>
            <div className="flex gap-2 pt-2">
              <Button
                disabled={running || gateway.isPending || !gatewayChanged || Boolean(gatewayError)}
                onClick={() => gateway.mutate(gatewayMAC.trim())}
              >
                Save baseline
              </Button>
              {saved && (
                <Button variant="outline" disabled={running || gateway.isPending} onClick={() => gateway.mutate("")}>
                  Use automatic
                </Button>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
      <Card className="bg-card/60">
        <CardHeader className="border-b">
          <div className="flex items-center gap-3">
            <span className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary">
              <Database className="size-4" />
            </span>
            <div>
              <CardTitle>History</CardTitle>
              <CardDescription>Manage durable device and gateway-security records</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-16 py-8">
          <div className="grid grid-cols-2 gap-3">
            <HistoryCount label="Device records" value={history?.devices} />
            <HistoryCount label="Conflict records" value={history?.conflicts} />
            <div className="col-span-2 rounded-lg border bg-background/30 p-4 text-xs">
              <HistoryDate label="Oldest observation" value={history?.oldest} />
              <HistoryDate label="Latest observation" value={history?.newest} />
            </div>
          </div>
          <div className="space-y-5">
            <div className="space-y-2">
              <Label htmlFor="history-age">Remove records older than</Label>
              <div className="flex gap-2">
                <NativeSelect
                  id="history-age"
                  value={pruneDays}
                  disabled={running}
                  onChange={(event) => setPruneDays(Number(event.target.value))}
                >
                  {[30, 60, 90, 180, 365].map((days) => (
                    <NativeSelectOption key={days} value={days}>
                      {days === 365 ? "1 year" : `${days} days`}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
                <Button variant="outline" disabled={running || prune.isPending} onClick={() => prune.mutate(pruneDays)}>
                  Prune history
                </Button>
              </div>
              <p className="text-[11px] text-muted-foreground">
                Local and gateway identity records are retained even when older.
              </p>
            </div>
            <div className="border-t pt-5">
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button
                    variant="destructive"
                    disabled={running || clear.isPending || (!history?.devices && !history?.conflicts)}
                  >
                    <Trash2 />
                    Clear all history
                  </Button>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle>Clear all network history?</AlertDialogTitle>
                    <AlertDialogDescription>
                      This permanently removes stored device observations and gateway conflicts. Settings and nicknames
                      are not affected.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction variant="destructive" onClick={() => clear.mutate()}>
                      Clear history
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            </div>
          </div>
        </CardContent>
      </Card>
      <Card className="bg-card/60">
        <CardHeader className="border-b">
          <CardTitle>Application data</CardTitle>
          <CardDescription>Open NetWarden’s local configuration and diagnostic locations</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2 py-6">
          <Button variant="outline" disabled={openConfig.isPending} onClick={() => openConfig.mutate()}>
            <FolderOpen />
            Open configuration directory
          </Button>
          <Button variant="outline" disabled={openLogs.isPending} onClick={() => openLogs.mutate()}>
            <FolderOpen />
            Open logs directory
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}

function HistoryCount({ label, value }: { label: string; value?: number }) {
  return (
    <div className="rounded-lg border bg-background/30 p-4">
      <p className="text-xs text-muted-foreground">{label}</p>
      <strong className="mt-1 block text-2xl">{value ?? "—"}</strong>
    </div>
  )
}
function HistoryDate({ label, value }: { label: string; value?: string }) {
  return (
    <div className="flex justify-between py-1">
      <span className="text-muted-foreground">{label}</span>
      <span>{value ? formatDate(value) : "No history"}</span>
    </div>
  )
}
