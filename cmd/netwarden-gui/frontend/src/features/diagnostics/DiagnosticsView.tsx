import { Activity, AlertTriangle, CheckCircle2, CircleX, RefreshCcw, ScanLine } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { QueryError } from "@/components/QueryError"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useRuntimeStatus } from "@/features/monitoring/monitoring.queries"
import { formatDate } from "@/lib/format"
import type { Activity as ActivityEvent } from "@/lib/wails/types"
import { useActivity } from "./diagnostics.queries"

export function DiagnosticsView() {
  const { data: status } = useRuntimeStatus()
  const { data: activity = [], isLoading, error, refetch } = useActivity()
  const dropped = (status?.DroppedEvents || 0) + (status?.SupervisorDroppedEvents || 0)
  const healthy = !status?.Rebuilding && !status?.LastPersistenceError

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
        <CardHeader className="flex-row items-center justify-between border-b">
          <div>
            <CardTitle>Runtime activity</CardTitle>
            <CardDescription>Recent lifecycle, discovery, device, and integrity events</CardDescription>
          </div>
          <Badge variant="outline">Last {activity.length} events</Badge>
        </CardHeader>
        <CardContent className="p-0">
          {error ? (
            <div className="p-4 sm:p-8">
              <QueryError error={error} retry={() => void refetch()} title="Could not load runtime activity" />
            </div>
          ) : isLoading ? (
            <div className="p-12 text-center text-sm text-muted-foreground">Loading activity…</div>
          ) : activity.length ? (
            <div className="overflow-x-auto">
              <Table className="min-w-[720px]">
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-44">Time</TableHead>
                    <TableHead className="w-28">Type</TableHead>
                    <TableHead>Event</TableHead>
                    <TableHead>Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {activity.map((event, index) => (
                    <ActivityRow key={`${event.at}-${event.kind}-${index}`} event={event} />
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="p-16 text-center">
              <Activity className="mx-auto size-9 text-muted-foreground" />
              <h3 className="mt-3 text-sm font-medium">No runtime activity yet</h3>
              <p className="mt-1 text-xs text-muted-foreground">Start monitoring to populate diagnostics.</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
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

function ActivityRow({ event }: { event: ActivityEvent }) {
  return (
    <TableRow>
      <TableCell className="text-xs text-muted-foreground">{formatDate(event.at)}</TableCell>
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
