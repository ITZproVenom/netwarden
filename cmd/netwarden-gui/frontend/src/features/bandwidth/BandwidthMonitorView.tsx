import { ArrowDown, ArrowUp, Gauge, LoaderCircle, Play, Square } from "lucide-react"
import type { ReactNode } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useDevices } from "@/features/devices/devices.queries"
import { isControlEligible } from "@/features/devices/device-list"
import { useRuntimeStatus } from "@/features/monitoring/monitoring.queries"
import type { BandwidthMeasurement } from "@/lib/wails/types"
import {
  useBandwidthMeasurements,
  useBandwidthMonitors,
  useStartBandwidthMonitor,
  useStopBandwidthMonitor,
} from "./monitor.queries"
import { useBandwidthLimits } from "./bandwidth.queries"
import { formatBytes, formatRate } from "./monitor-format"

export function BandwidthMonitorView() {
  const { data: status } = useRuntimeStatus()
  const running = Boolean(status?.Running)
  const available = running && Boolean(status?.BandwidthMonitoringAvailable)
  const { data: devices = [] } = useDevices()
  const { data: monitors = [] } = useBandwidthMonitors(available)
  const { data: measurements = [] } = useBandwidthMeasurements(available)
  const { data: limits = [] } = useBandwidthLimits()
  const start = useStartBandwidthMonitor()
  const stop = useStopBandwidthMonitor()
  const monitored = new Set(monitors.map((target) => target.mac.toLowerCase()))
  const limited = new Set(limits.map((target) => target.mac.toLowerCase()))
  const measurementByMAC = new Map(measurements.map((item) => [item.mac.toLowerCase(), item]))
  const rows = devices
    .filter((device) => device.role === "Device")
    .map((device) => ({ device, measurement: measurementByMAC.get(device.mac.toLowerCase()) }))
    .sort((left, right) => totalRate(right.measurement) - totalRate(left.measurement))
  const active = rows.filter((row) => monitored.has(row.device.mac.toLowerCase()))
  const busiest = active[0]
  const totals = active.reduce(
    (sum, row) => ({ upload: sum.upload + (row.measurement?.uploadBPS || 0), download: sum.download + (row.measurement?.downloadBPS || 0) }),
    { upload: 0, download: 0 },
  )

  return (
    <section className="space-y-5 py-7 sm:py-9">
      <div>
        <p className="mb-2 text-[10px] font-semibold tracking-[.18em] text-primary uppercase">Traffic visibility</p>
        <h2 className="text-2xl font-semibold tracking-tight">Bandwidth monitor</h2>
        <p className="mt-2 text-sm text-muted-foreground">Live per-device rates, totals, peaks, and one hour of recent history.</p>
      </div>
      <div className="grid gap-3 sm:grid-cols-3">
        <MetricCard label="Current download" value={formatRate(totals.download)} icon={<ArrowDown />} />
        <MetricCard label="Current upload" value={formatRate(totals.upload)} icon={<ArrowUp />} />
        <MetricCard label="Highest current usage" value={busiest ? busiest.device.name : "None"} icon={<Gauge />} />
      </div>
      <Card className="overflow-hidden bg-card/60">
        <CardHeader className="flex-row items-center justify-between border-b">
          <div>
            <CardTitle>Devices</CardTitle>
            <CardDescription>Monitoring routes remain active only while NetWarden is running.</CardDescription>
          </div>
          <Badge variant={available ? "outline" : "secondary"}>{available ? `${monitors.length} monitored` : "Unavailable"}</Badge>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table className="min-w-[980px]">
              <TableHeader>
                <TableRow>
                  <TableHead>Device</TableHead><TableHead>Live traffic</TableHead><TableHead>Total usage</TableHead>
                  <TableHead>Peak</TableHead><TableHead>Recent activity</TableHead><TableHead className="text-right">Monitor</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map(({ device, measurement }) => {
                  const isMonitored = monitored.has(device.mac.toLowerCase())
                  const pending = start.isPending || stop.isPending
                  return (
                    <TableRow key={device.mac}>
                      <TableCell><p className="text-sm font-medium">{device.name}</p><p className="font-mono text-[10px] text-muted-foreground">{device.ip}</p></TableCell>
                      <TableCell><p className="text-xs text-primary">↓ {formatRate(measurement?.downloadBPS || 0)}</p><p className="text-xs text-muted-foreground">↑ {formatRate(measurement?.uploadBPS || 0)}</p></TableCell>
                      <TableCell><p className="text-xs">↓ {formatBytes(measurement?.downloadBytes || 0)}</p><p className="text-xs text-muted-foreground">↑ {formatBytes(measurement?.uploadBytes || 0)}</p></TableCell>
                      <TableCell><p className="text-xs">↓ {formatRate(measurement?.peakDownloadBPS || 0)}</p><p className="text-xs text-muted-foreground">↑ {formatRate(measurement?.peakUploadBPS || 0)}</p></TableCell>
                      <TableCell><TrafficBars measurement={measurement} /></TableCell>
                      <TableCell className="text-right">
                        {isMonitored ? (
                          <Button size="sm" variant="outline" disabled={pending || limited.has(device.mac.toLowerCase())} title={limited.has(device.mac.toLowerCase()) ? "Remove the bandwidth limit before stopping monitoring" : undefined} onClick={() => stop.mutate(device.mac)}>{pending ? <LoaderCircle className="animate-spin" /> : <Square />} Stop</Button>
                        ) : (
                          <Button size="sm" disabled={!available || !isControlEligible(device) || pending} onClick={() => start.mutate({ ip: device.ip, mac: device.mac })}>{pending ? <LoaderCircle className="animate-spin" /> : <Play />} Start</Button>
                        )}
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </section>
  )
}

function MetricCard({ label, value, icon }: { label: string; value: string; icon: ReactNode }) {
  return <Card className="bg-card/60"><CardContent><p className="text-xs text-muted-foreground">{label}</p><div className="mt-2 flex items-center justify-between"><strong className="text-xl">{value}</strong><span className="text-primary [&>svg]:size-4">{icon}</span></div></CardContent></Card>
}

function TrafficBars({ measurement }: { measurement?: BandwidthMeasurement }) {
  const points = measurement?.history.slice(-30) || []
  const maximum = Math.max(1, ...points.map((point) => point.uploadBPS + point.downloadBPS))
  return <div className="flex h-8 w-36 items-end gap-px" aria-label="Recent bandwidth activity">{points.map((point) => <span key={point.at} className="min-w-0 flex-1 rounded-t-sm bg-primary/70" style={{ height: `${Math.max(8, ((point.uploadBPS + point.downloadBPS) / maximum) * 100)}%` }} />)}</div>
}

const totalRate = (measurement?: BandwidthMeasurement) => (measurement?.uploadBPS || 0) + (measurement?.downloadBPS || 0)
