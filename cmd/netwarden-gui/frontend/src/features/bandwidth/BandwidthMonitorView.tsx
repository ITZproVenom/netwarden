import { ArrowDown, ArrowUp, Gauge, LoaderCircle, Play, Square } from "lucide-react"
import type { ReactNode } from "react"
import { useEffect, useState } from "react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { useDevices } from "@/features/devices/devices.queries"
import { isControlEligible } from "@/features/devices/device-list"
import { useRuntimeStatus } from "@/features/monitoring/monitoring.queries"
import type { BandwidthHealth, BandwidthMeasurement } from "@/lib/wails/types"
import {
  useBandwidthMeasurements,
  useBandwidthMonitors,
  useStartBandwidthMonitor,
  useStopBandwidthMonitor,
  useBandwidthHealth,
  useBandwidthHistory,
  useStartAllBandwidthMonitors,
  useStopAllBandwidthMonitors,
} from "./monitor.queries"
import { useBandwidthLimits } from "./bandwidth.queries"
import { formatBytes, formatRate } from "./monitor-format"
import { useRateUnit } from "@/lib/measurement"

export function BandwidthMonitorView() {
  const { rateUnit } = useRateUnit()
  const { data: status } = useRuntimeStatus()
  const running = Boolean(status?.Running)
  const available = running && Boolean(status?.BandwidthMonitoringAvailable)
  const { data: devices = [] } = useDevices()
  const { data: monitors = [] } = useBandwidthMonitors(available)
  const { data: measurements = [] } = useBandwidthMeasurements(available)
  const { data: limits = [] } = useBandwidthLimits()
  const start = useStartBandwidthMonitor()
  const stop = useStopBandwidthMonitor()
  const startAll = useStartAllBandwidthMonitors()
  const stopAll = useStopAllBandwidthMonitors()
  const { data: health } = useBandwidthHealth(available)
  const [historyRange, setHistoryRange] = useState("hour")
  const [historyMAC, setHistoryMAC] = useState("")
  const monitored = new Set(monitors.map((target) => target.mac.toLowerCase()))
  const limited = new Set(limits.map((target) => target.mac.toLowerCase()))
  const measurementByMAC = new Map(measurements.map((item) => [item.mac.toLowerCase(), item]))
  const rows = devices
    .filter((device) => device.role === "Device")
    .map((device) => ({ device, measurement: measurementByMAC.get(device.mac.toLowerCase()) }))
    .sort((left, right) => totalRate(right.measurement) - totalRate(left.measurement))
  const active = rows.filter((row) => monitored.has(row.device.mac.toLowerCase()))
  const busiest = active[0]
  useEffect(() => { if (!historyMAC && busiest) setHistoryMAC(busiest.device.mac) }, [historyMAC, busiest])
  const { data: bucketHistory = [] } = useBandwidthHistory(historyMAC, historyRange, available)
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
        <MetricCard label="Current download" value={formatRate(totals.download, rateUnit)} icon={<ArrowDown />} />
        <MetricCard label="Current upload" value={formatRate(totals.upload, rateUnit)} icon={<ArrowUp />} />
        <MetricCard label="Highest current usage" value={busiest ? busiest.device.name : "None"} icon={<Gauge />} />
      </div>
      {(health?.samplingError || health?.queueDrops || health?.sendErrors) ? (
		<Alert variant={health.activeWarning ? "destructive" : "default"}><Gauge /><AlertTitle>
		  {health.activeWarning ? "Bandwidth monitor health warning" : "Bandwidth monitor recovered"}
		</AlertTitle><AlertDescription>
		  {health.samplingError || <BandwidthHealthDetails health={health} devices={devices} />}
        </AlertDescription></Alert>
      ) : null}
      <Card className="overflow-hidden bg-card/60">
        <CardHeader className="flex-row items-center justify-between border-b">
          <div>
            <CardTitle>Devices</CardTitle>
            <CardDescription>Monitoring routes remain active only while NetWarden is running.</CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" disabled={!available || startAll.isPending} onClick={() => startAll.mutate()}><Play /> Monitor all</Button>
            <Button size="sm" variant="outline" disabled={!monitors.length || stopAll.isPending || limits.length > 0} onClick={() => stopAll.mutate()}><Square /> Stop all</Button>
            <Badge variant={available ? "outline" : "secondary"}>{available ? `${monitors.length} monitored` : "Unavailable"}</Badge>
          </div>
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
                      <TableCell><p className="text-xs text-primary">↓ {formatRate(measurement?.downloadBPS || 0, rateUnit)}</p><p className="text-xs text-muted-foreground">↑ {formatRate(measurement?.uploadBPS || 0, rateUnit)}</p></TableCell>
                      <TableCell><p className="text-xs">↓ {formatBytes(measurement?.downloadBytes || 0)}</p><p className="text-xs text-muted-foreground">↑ {formatBytes(measurement?.uploadBytes || 0)}</p></TableCell>
                      <TableCell><p className="text-xs">↓ {formatRate(measurement?.peakDownloadBPS || 0, rateUnit)}</p><p className="text-xs text-muted-foreground">↑ {formatRate(measurement?.peakUploadBPS || 0, rateUnit)}</p></TableCell>
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
      <Card className="bg-card/60">
        <CardHeader className="flex-row items-center justify-between"><div><CardTitle>Usage history</CardTitle><CardDescription>Persistent compact usage buckets</CardDescription></div>
          <div className="flex gap-2"><NativeSelect value={historyMAC} onChange={(event) => setHistoryMAC(event.target.value)}>{rows.map(({device}) => <NativeSelectOption key={device.mac} value={device.mac}>{device.name}</NativeSelectOption>)}</NativeSelect>
          <NativeSelect value={historyRange} onChange={(event) => setHistoryRange(event.target.value)}><NativeSelectOption value="hour">Last hour</NativeSelectOption><NativeSelectOption value="day">Last day</NativeSelectOption><NativeSelectOption value="week">Last week</NativeSelectOption><NativeSelectOption value="month">Last month</NativeSelectOption></NativeSelect></div>
        </CardHeader>
        <CardContent><HistoryBars buckets={bucketHistory} /></CardContent>
      </Card>
    </section>
  )
}

function BandwidthHealthDetails({ health, devices }: {
	health: BandwidthHealth
	devices: { mac: string; name: string }[]
}) {
	const top = [...health.deviceQueueDrops].sort((left, right) =>
		(right.uploadDrops + right.downloadDrops) - (left.uploadDrops + left.downloadDrops))[0]
	const deviceName = top && devices.find((device) => device.mac.toLowerCase() === top.mac.toLowerCase())?.name
	return <span className="space-y-1">
		<span className="block">
			{health.queueDrops} queued packets dropped since monitoring started
			{health.sampleSeconds ? ` · ${health.recentQueueDrops} in the last ${health.sampleSeconds}s` : ""}
			{` · ${health.sendErrors} forwarding errors`}
		</span>
		{health.sampleSeconds ? <span className="block text-xs">
			{`Latest sample: ${health.recentQueueDrops} queue drops · ${health.recentSendErrors} forwarding errors`}
		</span> : null}
		<span className="block text-xs">
			{`Upload ${health.uploadQueueDrops} · download ${health.downloadQueueDrops} · monitoring-only ${health.monitorQueueDrops} · limited ${health.limitedQueueDrops}`}
		</span>
		<span className="block text-xs">
			{`Queue now: upload ${health.uploadQueueDepth}/${health.queueCapacity}, download ${health.downloadQueueDepth}/${health.queueCapacity} · peak: ${health.peakUploadDepth}/${health.peakDownloadDepth}`}
		</span>
		<span className="block text-xs">
			{`Buffered now: upload ${formatBytes(health.uploadQueueBytes)}, download ${formatBytes(health.downloadQueueBytes)} of ${formatBytes(health.queueByteCapacity)} · peak: ${formatBytes(health.peakUploadBytes)}/${formatBytes(health.peakDownloadBytes)}`}
		</span>
		{top ? <span className="block text-xs">
			{`Most affected: ${deviceName || top.mac} · upload ${top.uploadDrops}, download ${top.downloadDrops}`}
		</span> : null}
	</span>
}

function HistoryBars({ buckets }: { buckets: Array<{ start: string; uploadBytes: number; downloadBytes: number }> }) {
  const points = buckets.slice(-96)
  const maximum = Math.max(1, ...points.map((point) => point.uploadBytes + point.downloadBytes))
  if (!points.length) return <p className="py-8 text-center text-xs text-muted-foreground">No usage recorded for this range.</p>
  return <div className="flex h-40 items-end gap-px" aria-label="Historical bandwidth usage">{points.map((point) => <div key={point.start} title={`${new Date(point.start).toLocaleString()} · ${formatBytes(point.uploadBytes + point.downloadBytes)}`} className="min-w-0 flex-1 rounded-t-sm bg-primary/70" style={{height: `${Math.max(2, ((point.uploadBytes + point.downloadBytes) / maximum) * 100)}%`}} />)}</div>
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
