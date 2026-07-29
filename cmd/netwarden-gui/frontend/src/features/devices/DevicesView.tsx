import { useMemo, useRef, useState } from "react"
import { ArrowDownAZ, Ban, ChevronRight, LoaderCircle, RotateCcw, Search, X } from "lucide-react"
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
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { QueryError } from "@/components/QueryError"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useDisconnectAllDevices, useRestoreAllControls } from "@/features/control/control.queries"
import { formatDate } from "@/lib/format"
import { useStoredState } from "@/lib/preferences"
import type { Device } from "@/lib/wails/types"
import { DeviceDetails } from "./DeviceDetails"
import { useDevices } from "./devices.queries"

type SortKey = "name" | "ip" | "vendor" | "role" | "lastSeen" | "online" | "controlState"
type DevicePreferences = { query: string; presence: string; role: string; sortBy: SortKey; descending: boolean }
const defaults: DevicePreferences = { query: "", presence: "online", role: "Device", sortBy: "name", descending: false }

export function DevicesView() {
  const { data: devices = [], isLoading, error, refetch } = useDevices()
  const [preferences, setPreferences] = useStoredState<DevicePreferences>("netwarden.devices", defaults)
  const [selectedMAC, setSelectedMAC] = useState("")
  const drawerTrigger = useRef<HTMLElement | null>(null)
  const restoreAll = useRestoreAllControls()
  const disconnectAll = useDisconnectAllDevices()
  const update = <K extends keyof DevicePreferences>(key: K, value: DevicePreferences[K]) =>
    setPreferences((current) => ({ ...current, [key]: value }))
  const filtered =
    preferences.query !== "" ||
    preferences.presence !== defaults.presence ||
    preferences.role !== defaults.role ||
    preferences.sortBy !== defaults.sortBy ||
    preferences.descending
  const controlledCount = devices.filter((device) => device.controlState !== "").length
  const eligibleCount = devices.filter(
    (device) => device.online && device.role === "Device" && device.controlState === "",
  ).length
  const visible = useMemo(
    () =>
      devices
        .filter((device) =>
          `${device.name} ${device.ip} ${device.mac} ${device.vendor}`
            .toLowerCase()
            .includes(preferences.query.toLowerCase()),
        )
        .filter((device) => preferences.presence === "all" || (preferences.presence === "online") === device.online)
        .filter((device) => preferences.role === "all" || device.role === preferences.role)
        .sort((left, right) => {
          const leftValue =
            preferences.sortBy === "lastSeen" ? new Date(left.lastSeen).getTime() : left[preferences.sortBy]
          const rightValue =
            preferences.sortBy === "lastSeen" ? new Date(right.lastSeen).getTime() : right[preferences.sortBy]
          const result =
            typeof leftValue === "number" || typeof leftValue === "boolean"
              ? Number(leftValue) - Number(rightValue)
              : String(leftValue).localeCompare(String(rightValue), undefined, {
                  numeric: preferences.sortBy === "ip",
                  sensitivity: "base",
                })
          return preferences.descending ? -result : result
        }),
    [devices, preferences],
  )
  const selected = devices.find((device) => device.mac === selectedMAC)
  const closeDetails = () => {
    setSelectedMAC("")
    window.requestAnimationFrame(() => drawerTrigger.current?.focus())
  }

  return (
    <>
      <Card className="overflow-hidden bg-card/60">
        <CardHeader className="gap-4 border-b">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <CardTitle>Devices</CardTitle>
              <CardDescription>
                {visible.length} of {devices.length} known hosts
              </CardDescription>
            </div>
            <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
              {eligibleCount > 0 && (
                <DisconnectAll
                  count={eligibleCount}
                  pending={disconnectAll.isPending}
                  disconnect={() => disconnectAll.mutate()}
                />
              )}
              {controlledCount > 0 && (
                <RestoreAll
                  count={controlledCount}
                  pending={restoreAll.isPending}
                  restore={() => restoreAll.mutate()}
                />
              )}
              <div className="relative min-w-0 flex-1 sm:w-64 sm:flex-none">
                <Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  className="pl-9"
                  placeholder="Search devices…"
                  value={preferences.query}
                  onChange={(event) => update("query", event.target.value)}
                />
              </div>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <NativeSelect
              aria-label="Filter by status"
              value={preferences.presence}
              onChange={(event) => update("presence", event.target.value)}
            >
              <NativeSelectOption value="all">All statuses</NativeSelectOption>
              <NativeSelectOption value="online">Online</NativeSelectOption>
              <NativeSelectOption value="offline">Offline</NativeSelectOption>
            </NativeSelect>
            <NativeSelect
              aria-label="Filter by role"
              value={preferences.role}
              onChange={(event) => update("role", event.target.value)}
            >
              <NativeSelectOption value="all">All roles</NativeSelectOption>
              <NativeSelectOption value="Device">Devices</NativeSelectOption>
              <NativeSelectOption value="Gateway">Gateway</NativeSelectOption>
              <NativeSelectOption value="This device">This device</NativeSelectOption>
            </NativeSelect>
            <NativeSelect
              aria-label="Sort devices"
              value={preferences.sortBy}
              onChange={(event) => update("sortBy", event.target.value as SortKey)}
            >
              <NativeSelectOption value="name">Sort by name</NativeSelectOption>
              <NativeSelectOption value="ip">Sort by IP address</NativeSelectOption>
              <NativeSelectOption value="vendor">Sort by vendor</NativeSelectOption>
              <NativeSelectOption value="role">Sort by role</NativeSelectOption>
              <NativeSelectOption value="online">Sort by online status</NativeSelectOption>
              <NativeSelectOption value="controlState">Sort by control status</NativeSelectOption>
              <NativeSelectOption value="lastSeen">Sort by last seen</NativeSelectOption>
            </NativeSelect>
            <Button
              variant="outline"
              size="icon"
              aria-label={preferences.descending ? "Sort ascending" : "Sort descending"}
              onClick={() => update("descending", !preferences.descending)}
            >
              <ArrowDownAZ className={preferences.descending ? "rotate-180" : ""} />
            </Button>
            {filtered && (
              <Button variant="ghost" size="sm" onClick={() => setPreferences(defaults)}>
                <X />
                Clear filters
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {(disconnectAll.isPending || restoreAll.isPending) && (
            <BulkProgress
              count={disconnectAll.isPending ? eligibleCount : controlledCount}
              operation={disconnectAll.isPending ? "Disconnecting devices" : "Restoring devices"}
            />
          )}
          {error ? (
            <div className="p-4 sm:p-8">
              <QueryError error={error} retry={() => void refetch()} title="Could not load devices" />
            </div>
          ) : isLoading ? (
            <div className="p-12 text-center text-sm text-muted-foreground">Loading devices…</div>
          ) : visible.length ? (
            <div className="overflow-x-auto">
              <Table className="min-w-[900px]">
                <TableHeader>
                  <TableRow>
                    <TableHead>Device</TableHead>
                    <TableHead>Address</TableHead>
                    <TableHead>Vendor</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Control</TableHead>
                    <TableHead>Last seen</TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visible.map((device) => (
                    <DeviceRow
                      key={device.mac}
                      device={device}
                      onOpen={(trigger) => {
                        drawerTrigger.current = trigger
                        setSelectedMAC(device.mac)
                      }}
                    />
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="p-16 text-center">
              <h3 className="text-sm font-medium">No devices match these filters</h3>
              <p className="mt-1 text-xs text-muted-foreground">Adjust or clear the filters to see more hosts.</p>
              {filtered && (
                <Button className="mt-4" variant="outline" size="sm" onClick={() => setPreferences(defaults)}>
                  Clear filters
                </Button>
              )}
            </div>
          )}
        </CardContent>
      </Card>
      <DeviceDetails device={selected} onClose={closeDetails} />
    </>
  )
}

function BulkProgress({ count, operation }: { count: number; operation: string }) {
  return (
    <div className="border-b bg-primary/8 px-4 py-4" role="status" aria-live="polite" aria-atomic="true">
      <div className="mb-2 flex items-center justify-between gap-4 text-sm font-medium">
        <span className="flex items-center gap-2">
          <LoaderCircle className="size-4 animate-spin text-primary" />
          {operation}
        </span>
        <span className="text-xs text-muted-foreground">
          {count} target{count === 1 ? "" : "s"}
        </span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-muted" aria-hidden="true">
        <div className="h-full w-2/3 animate-pulse rounded-full bg-primary shadow-[0_0_12px_var(--primary)]" />
      </div>
      <p className="mt-2 text-xs text-muted-foreground">Keep NetWarden open while the network operation completes.</p>
    </div>
  )
}

function DisconnectAll({ count, pending, disconnect }: { count: number; pending: boolean; disconnect: () => void }) {
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="destructive" disabled={pending}>
          {pending ? <LoaderCircle className="animate-spin" /> : <Ban />}Disconnect all ({count})
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Disconnect every eligible device?</AlertDialogTitle>
          <AlertDialogDescription>
            This will interrupt gateway access for {count} online device{count === 1 ? "" : "s"}. NetWarden will roll
            back previously changed targets if any device fails. Your computer and gateway are always excluded.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction variant="destructive" onClick={disconnect}>
            Disconnect all devices
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

function RestoreAll({ count, pending, restore }: { count: number; pending: boolean; restore: () => void }) {
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="outline" disabled={pending}>
          {pending ? <LoaderCircle className="animate-spin" /> : <RotateCcw />}Restore all ({count})
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Restore all controlled devices?</AlertDialogTitle>
          <AlertDialogDescription>
            This stops active control and restores normal network access for {count} device{count === 1 ? "" : "s"}.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={restore}>Restore all</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}

function DeviceRow({ device, onOpen }: { device: Device; onOpen: (trigger: HTMLElement) => void }) {
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
      <TableCell className="text-xs text-muted-foreground">{formatDate(device.lastSeen)}</TableCell>
      <TableCell>
        <ChevronRight className="size-4 text-muted-foreground" />
      </TableCell>
    </TableRow>
  )
}
