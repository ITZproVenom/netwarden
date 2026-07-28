import { useMemo, useState } from "react"
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  CircleX,
  Copy,
  Download,
  RefreshCcw,
  ScanLine,
  Search,
} from "lucide-react"
import { toast } from "sonner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { QueryError } from "@/components/QueryError"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useControlAudit } from "@/features/control/control.queries"
import { useRuntimeStatus } from "@/features/monitoring/monitoring.queries"
import { formatDate, formatRelativeDate } from "@/lib/format"
import { copyText } from "@/lib/wails/clipboard"
import type { Activity as ActivityEvent, RuntimeStatus } from "@/lib/wails/types"
import { useActivity } from "./diagnostics.queries"

type UnifiedEvent = ActivityEvent & { source: "runtime" | "control" }

export function DiagnosticsView() {
  const { data: status } = useRuntimeStatus()
  const runtime = useActivity()
  const control = useControlAudit()
  const [query, setQuery] = useState("")
  const [severity, setSeverity] = useState("all")
  const [kind, setKind] = useState("all")
  const events = useMemo<UnifiedEvent[]>(
    () =>
      [
        ...(runtime.data || []).map((event) => ({ ...event, source: "runtime" as const })),
        ...(control.data || []).map((event) => ({
          at: event.at,
          kind: `control:${event.operation}`,
          severity: controlSeverity(event.outcome),
          title: controlTitle(event.operation),
          detail: `${event.outcome.replaceAll("_", " ")}${event.targets.length ? ` · ${event.targets.join(", ")}` : ""}`,
          source: "control" as const,
        })),
      ].sort((left, right) => new Date(right.at).getTime() - new Date(left.at).getTime()),
    [runtime.data, control.data],
  )
  const kinds = useMemo(() => [...new Set(events.map((event) => event.kind))].sort(), [events])
  const visible = events
    .filter((event) => severity === "all" || event.severity === severity)
    .filter((event) => kind === "all" || event.kind === kind)
    .filter((event) => `${event.kind} ${event.title} ${event.detail || ""}`.toLowerCase().includes(query.toLowerCase()))
  const error = runtime.error || control.error
  const dropped = (status?.DroppedEvents || 0) + (status?.SupervisorDroppedEvents || 0)
  const healthy = !status?.Rebuilding && !status?.LastPersistenceError
  const report = () => ({ generatedAt: new Date().toISOString(), status, events })
  const copySummary = async () => {
    try {
      await copyText(supportSummary(status, events))
      toast.success("Support summary copied")
    } catch (error) {
      toast.error("Could not copy support summary", {
        description: error instanceof Error ? error.message : "Unknown error",
      })
    }
  }
  const exportReport = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(report(), null, 2)], { type: "application/json" }))
    const link = document.createElement("a")
    link.href = url
    link.download = `netwarden-diagnostics-${new Date().toISOString().replaceAll(":", "-")}.json`
    link.click()
    URL.revokeObjectURL(url)
    toast.success("Diagnostics exported")
  }

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric
          label="Runtime health"
          value={healthy ? "Healthy" : "Attention"}
          icon={healthy ? CheckCircle2 : AlertTriangle}
          warning={!healthy}
        />
        <Metric label="Generation" value={status?.Generation || "—"} icon={Activity} />
        <Metric
          label="Restarts"
          value={status?.RestartCount || 0}
          icon={RefreshCcw}
          warning={Boolean(status?.RestartCount)}
        />
        <Metric label="Dropped events" value={dropped} icon={ScanLine} warning={dropped > 0} />
      </div>
      {status?.LastRestartReason && (
        <Alert variant="destructive">
          <AlertTriangle />
          <AlertTitle>Last runtime restart</AlertTitle>
          <AlertDescription>{status.LastRestartReason}</AlertDescription>
        </Alert>
      )}
      {status?.LastPersistenceError && (
        <Alert variant="destructive">
          <CircleX />
          <AlertTitle>History persistence error</AlertTitle>
          <AlertDescription>{status.LastPersistenceError}</AlertDescription>
        </Alert>
      )}
      <Card className="overflow-hidden bg-card/60">
        <CardHeader className="gap-4 border-b">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <CardTitle>Unified activity</CardTitle>
              <CardDescription>Runtime, discovery, integrity, device, and control audit events</CardDescription>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button variant="outline" size="sm" onClick={() => void copySummary()}>
                <Copy />
                Copy summary
              </Button>
              <Button variant="outline" size="sm" onClick={exportReport}>
                <Download />
                Export JSON
              </Button>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <div className="relative min-w-52 flex-1">
              <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                className="pl-9"
                placeholder="Search activity…"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </div>
            <NativeSelect
              aria-label="Filter by severity"
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
            >
              <NativeSelectOption value="all">All severities</NativeSelectOption>
              <NativeSelectOption value="info">Info</NativeSelectOption>
              <NativeSelectOption value="warning">Warning</NativeSelectOption>
              <NativeSelectOption value="error">Error</NativeSelectOption>
            </NativeSelect>
            <NativeSelect
              aria-label="Filter by event type"
              value={kind}
              onChange={(event) => setKind(event.target.value)}
            >
              <NativeSelectOption value="all">All event types</NativeSelectOption>
              {kinds.map((value) => (
                <NativeSelectOption key={value} value={value}>
                  {value}
                </NativeSelectOption>
              ))}
            </NativeSelect>
            <Badge variant="outline">
              {visible.length} of {events.length}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {error ? (
            <div className="p-4 sm:p-8">
              <QueryError
                error={error}
                retry={() => {
                  void runtime.refetch()
                  void control.refetch()
                }}
                title="Could not load activity"
              />
            </div>
          ) : runtime.isLoading || control.isLoading ? (
            <div className="p-12 text-center text-sm text-muted-foreground">Loading activity…</div>
          ) : visible.length ? (
            <div className="overflow-x-auto">
              <Table className="min-w-[760px]">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-36">Time</TableHead>
                    <TableHead className="w-36">Type</TableHead>
                    <TableHead>Event</TableHead>
                    <TableHead>Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visible.map((event, index) => (
                    <ActivityRow key={`${event.source}-${event.at}-${event.kind}-${index}`} event={event} />
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="p-16 text-center">
              <Activity className="mx-auto size-9 text-muted-foreground" />
              <h3 className="mt-3 text-sm font-medium">
                {events.length ? "No activity matches these filters" : "No activity yet"}
              </h3>
              <p className="mt-1 text-xs text-muted-foreground">
                {events.length ? "Adjust the search or filters." : "Start monitoring to populate diagnostics."}
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function controlSeverity(outcome: string): ActivityEvent["severity"] {
  const value = outcome.toLowerCase()
  return value.includes("fail") || value.includes("error")
    ? "error"
    : value.includes("ready") || value.includes("pending")
      ? "warning"
      : "info"
}
function controlTitle(operation: string) {
  return `Control ${operation.replaceAll("_", " ")}`
}
function supportSummary(status: RuntimeStatus | undefined, events: UnifiedEvent[]) {
  return [
    `NetWarden support summary`,
    `Generated: ${new Date().toISOString()}`,
    `Running: ${Boolean(status?.Running)}`,
    `Generation: ${status?.Generation ?? "unknown"}`,
    `Restarts: ${status?.RestartCount ?? "unknown"}`,
    `Dropped events: ${(status?.DroppedEvents || 0) + (status?.SupervisorDroppedEvents || 0)}`,
    `Conflicts: ${status?.ConflictCount ?? "unknown"}`,
    `Persistence error: ${status?.LastPersistenceError || "none"}`,
    `Recent events:`,
    ...events
      .slice(0, 25)
      .map(
        (event) =>
          `${event.at} [${event.severity}] ${event.kind}: ${event.title}${event.detail ? ` — ${event.detail}` : ""}`,
      ),
  ].join("\n")
}
function Metric({
  label,
  value,
  icon: Icon,
  warning = false,
}: {
  label: string
  value: string | number
  icon: typeof Activity
  warning?: boolean
}) {
  return (
    <Card className="bg-card/60">
      <CardContent>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-muted-foreground">{label}</p>
            <strong className={warning ? "mt-2 block text-xl text-amber-500" : "mt-2 block text-xl"}>{value}</strong>
          </div>
          <Icon className={warning ? "size-5 text-amber-500" : "size-5 text-primary"} />
        </div>
      </CardContent>
    </Card>
  )
}
function ActivityRow({ event }: { event: UnifiedEvent }) {
  return (
    <TableRow>
      <TableCell className="text-xs text-muted-foreground" title={formatDate(event.at)}>
        {formatRelativeDate(event.at)}
      </TableCell>
      <TableCell>
        <Badge
          variant={event.severity === "error" ? "destructive" : event.severity === "warning" ? "outline" : "secondary"}
        >
          {event.kind}
        </Badge>
      </TableCell>
      <TableCell className="font-medium">{event.title}</TableCell>
      <TableCell className="max-w-xl truncate text-xs text-muted-foreground" title={event.detail}>
        {event.detail || "—"}
      </TableCell>
    </TableRow>
  )
}
