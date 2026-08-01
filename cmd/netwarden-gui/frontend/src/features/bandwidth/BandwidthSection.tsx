import { useEffect, useState } from "react"
import { Gauge, LoaderCircle, RotateCcw } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import type { BandwidthLimit, Device } from "@/lib/wails/types"
import { useRemoveBandwidthLimit, useSetBandwidthLimit } from "./bandwidth.queries"
import { displayMbps } from "./format"
import { bandwidthValidation, parseMbps } from "./validation"
import { useStartBandwidthMonitor, useStopBandwidthMonitor } from "./monitor.queries"

const isBandwidthEligible = (device: Device) =>
  device.online && device.role === "Device" && device.controlState === ""

export function BandwidthSection({
  device,
  limit,
  available,
  monitoringAvailable,
  monitored,
}: {
  device: Device
  limit?: BandwidthLimit
  available: boolean
  monitoringAvailable: boolean
  monitored: boolean
}) {
  const [download, setDownload] = useState("")
  const [upload, setUpload] = useState("")
  const setLimit = useSetBandwidthLimit()
  const removeLimit = useRemoveBandwidthLimit()
  const startMonitor = useStartBandwidthMonitor()
  const stopMonitor = useStopBandwidthMonitor()
  useEffect(() => {
    setDownload(limit?.downloadBitsPerSecond ? displayMbps(limit.downloadBitsPerSecond) : "")
    setUpload(limit?.uploadBitsPerSecond ? displayMbps(limit.uploadBitsPerSecond) : "")
  }, [device.mac, limit?.downloadBitsPerSecond, limit?.uploadBitsPerSecond])
  const validation = bandwidthValidation(download, upload)
  const eligible = available && isBandwidthEligible(device)
  const pending = setLimit.isPending || removeLimit.isPending
  const reason = !available
    ? "Bandwidth control is unavailable with the active capture backend."
      : device.role !== "Device"
        ? "This protected network endpoint cannot be limited."
        : device.controlState !== ""
        ? "Restore normal access before applying a bandwidth limit."
        : !device.online
          ? "The device must be online before applying a limit."
          : "Set either direction to 0 to leave it unlimited."
  return (
    <section className="space-y-4 py-6">
      <div className="flex items-center justify-between gap-3 rounded-lg border bg-background/30 p-3">
        <div><h4 className="text-xs font-semibold">Traffic monitoring</h4><p className="mt-1 text-xs text-muted-foreground">Measure live rates, totals, peaks, and history.</p></div>
        {monitored ? <Button size="sm" variant="outline" disabled={Boolean(limit) || stopMonitor.isPending} onClick={() => stopMonitor.mutate(device.mac)}><RotateCcw /> Stop</Button> : <Button size="sm" variant="outline" disabled={!monitoringAvailable || !isBandwidthEligible(device) || startMonitor.isPending} onClick={() => startMonitor.mutate({ip: device.ip, mac: device.mac})}><Gauge /> Start</Button>}
      </div>
      <div className="flex items-center justify-between gap-3">
        <div>
          <h4 className="text-xs font-semibold">Bandwidth limit</h4>
          <p className="mt-1 text-xs text-muted-foreground">Limit traffic while NetWarden is running.</p>
        </div>
        <Badge variant={limit ? "default" : eligible ? "outline" : "secondary"}>
          {pending && <LoaderCircle className="animate-spin" />}
          {limit ? "Limited" : eligible ? "Available" : "Unavailable"}
        </Badge>
      </div>
      {limit && (
        <div className="rounded-lg border bg-background/30 p-3 text-xs">
          <div className="flex justify-between gap-3 py-1">
            <span className="text-muted-foreground">Download</span>
            <span>
              {limit.downloadBitsPerSecond ? `${displayMbps(limit.downloadBitsPerSecond)} Mbps` : "Unlimited"}
            </span>
          </div>
          <div className="flex justify-between gap-3 py-1">
            <span className="text-muted-foreground">Upload</span>
            <span>{limit.uploadBitsPerSecond ? `${displayMbps(limit.uploadBitsPerSecond)} Mbps` : "Unlimited"}</span>
          </div>
        </div>
      )}
      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-2">
          <Label htmlFor={`download-limit-${device.mac}`}>Download Mbps</Label>
          <Input
            id={`download-limit-${device.mac}`}
            type="number"
            inputMode="decimal"
            min="0"
            step="0.1"
            placeholder="Unlimited"
            value={download}
            disabled={!eligible || pending}
            onChange={(event) => setDownload(event.target.value)}
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor={`upload-limit-${device.mac}`}>Upload Mbps</Label>
          <Input
            id={`upload-limit-${device.mac}`}
            type="number"
            inputMode="decimal"
            min="0"
            step="0.1"
            placeholder="Unlimited"
            value={upload}
            disabled={!eligible || pending}
            onChange={(event) => setUpload(event.target.value)}
          />
        </div>
      </div>
      <p className={`text-xs ${eligible && validation ? "text-destructive" : "text-muted-foreground"}`}>
        {eligible && validation ? validation : reason}
      </p>
      <div className="flex flex-wrap gap-2">
        <Button
          size="sm"
          disabled={!eligible || pending || Boolean(validation)}
          onClick={() =>
            setLimit.mutate({
              ip: device.ip,
              mac: device.mac,
              downloadBitsPerSecond: parseMbps(download) ?? 0,
              uploadBitsPerSecond: parseMbps(upload) ?? 0,
            })
          }
        >
          <Gauge />
          {limit ? "Update limit" : "Apply limit"}
        </Button>
        {limit && (
          <Button variant="outline" size="sm" disabled={pending} onClick={() => removeLimit.mutate(device.mac)}>
            <RotateCcw />
            Remove limit
          </Button>
        )}
      </div>
    </section>
  )
}
