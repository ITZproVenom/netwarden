import { useEffect, useRef } from "react"
import { ChevronRight, LoaderCircle } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { formatDate } from "@/lib/format"
import type { Device } from "@/lib/wails/types"
import type { BandwidthLimit } from "@/lib/wails/types"
import { bandwidthSummary } from "@/features/bandwidth/format"
import { isControlEligible } from "./device-list"

export function DeviceTable({
  devices,
  bandwidthByMAC,
  checkedMACs,
  onCheckedChange,
  onCheckVisible,
  onOpen,
}: {
  devices: Device[]
  bandwidthByMAC: Map<string, BandwidthLimit>
  checkedMACs: Set<string>
  onCheckedChange: (mac: string, checked: boolean) => void
  onCheckVisible: (checked: boolean) => void
  onOpen: (device: Device, trigger: HTMLElement) => void
}) {
  const eligible = devices.filter(
    (device) => isControlEligible(device) && !bandwidthByMAC.has(device.mac.toLowerCase()),
  )
  const allChecked = eligible.length > 0 && eligible.every((device) => checkedMACs.has(device.mac))
  const someChecked = eligible.some((device) => checkedMACs.has(device.mac))
  return (
    <div className="overflow-x-auto">
      <Table className="min-w-[1150px]">
        <TableHeader>
          <TableRow>
            <TableHead className="w-10">
              <SelectionCheckbox
                label="Select all eligible visible devices"
                checked={allChecked}
                indeterminate={someChecked && !allChecked}
                disabled={eligible.length === 0}
                onChange={onCheckVisible}
              />
            </TableHead>
            <TableHead>Device</TableHead>
            <TableHead>Address</TableHead>
            <TableHead>Vendor</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>Role</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Control</TableHead>
            <TableHead>Bandwidth</TableHead>
            <TableHead>Last seen</TableHead>
            <TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {devices.map((device) => (
            <DeviceRow
              key={device.mac}
              device={device}
              bandwidthLimit={bandwidthByMAC.get(device.mac.toLowerCase())}
              checked={checkedMACs.has(device.mac)}
              onCheckedChange={(checked) => onCheckedChange(device.mac, checked)}
              onOpen={(trigger) => onOpen(device, trigger)}
            />
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

function DeviceRow({
  device,
  bandwidthLimit,
  checked,
  onCheckedChange,
  onOpen,
}: {
  device: Device
  bandwidthLimit?: BandwidthLimit
  checked: boolean
  onCheckedChange: (checked: boolean) => void
  onOpen: (trigger: HTMLElement) => void
}) {
  const controlled = device.controlState !== ""
  const control =
    device.controlState === "active"
      ? "Disconnected"
      : device.controlState === "continuous"
        ? "Continuous"
        : device.controlState === "restoring"
          ? "Restoring"
          : device.controlState === "failed"
            ? "Recovery failed"
            : device.role !== "Device"
              ? "Protected"
              : device.online
                ? "Available"
                : "Offline"
  return (
    <TableRow
      tabIndex={0}
      role="button"
      aria-label={`Open details for ${device.name || device.ip}`}
      className="cursor-pointer focus-visible:bg-accent focus-visible:outline-none"
      onClick={(event) => onOpen(event.currentTarget)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault()
          onOpen(event.currentTarget)
        }
      }}
    >
      <TableCell onClick={(event) => event.stopPropagation()} onKeyDown={(event) => event.stopPropagation()}>
        <SelectionCheckbox
          label={`Select ${device.name || device.ip}`}
          checked={checked}
          disabled={!isControlEligible(device) || Boolean(bandwidthLimit)}
          onChange={onCheckedChange}
        />
      </TableCell>
      <TableCell>
        <div className="flex items-center gap-3">
          <span
            className={`size-2 rounded-full ${device.online ? "bg-primary shadow-[0_0_8px_var(--primary)]" : "bg-muted-foreground/60"}`}
          />
          <div>
            <p className="font-medium">{device.name || device.ip}</p>
            <p className="font-mono text-[10px] text-muted-foreground">{device.mac}</p>
          </div>
        </div>
      </TableCell>
      <TableCell>{device.ip}</TableCell>
      <TableCell className="max-w-48 truncate text-muted-foreground" title={device.vendor}>
        {device.vendor || "Unknown"}
      </TableCell>
      <TableCell>
        <Badge variant="secondary">{device.type || "Unknown"}</Badge>
      </TableCell>
      <TableCell>
        <Badge variant="outline">{device.role}</Badge>
      </TableCell>
      <TableCell>
        <Badge variant={device.online ? "default" : "secondary"}>{device.online ? "Online" : "Offline"}</Badge>
      </TableCell>
      <TableCell>
        <Badge variant={controlled ? "destructive" : "secondary"}>
          {device.controlState === "restoring" && <LoaderCircle className="animate-spin" />}
          {control}
        </Badge>
      </TableCell>
      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
        {bandwidthSummary(bandwidthLimit)}
      </TableCell>
      <TableCell className="text-xs text-muted-foreground">{formatDate(device.lastSeen)}</TableCell>
      <TableCell>
        <ChevronRight className="size-4 text-muted-foreground" />
      </TableCell>
    </TableRow>
  )
}

function SelectionCheckbox({
  label,
  checked,
  indeterminate = false,
  disabled = false,
  onChange,
}: {
  label: string
  checked: boolean
  indeterminate?: boolean
  disabled?: boolean
  onChange: (checked: boolean) => void
}) {
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = indeterminate
  }, [indeterminate])
  return (
    <input
      ref={ref}
      type="checkbox"
      className="size-4 rounded border-border accent-primary disabled:cursor-not-allowed disabled:opacity-40"
      aria-label={label}
      checked={checked}
      disabled={disabled}
      onChange={(event) => onChange(event.target.checked)}
    />
  )
}
