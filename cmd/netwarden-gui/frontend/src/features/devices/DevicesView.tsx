import { useEffect, useMemo, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { QueryError } from "@/components/QueryError"
import { useDisconnectSelectedDevices, useRestoreAllControls } from "@/features/control/control.queries"
import { MonitoringOverview } from "@/features/monitoring/MonitoringOverview"
import { useBandwidthLimits, useClearBandwidthLimits } from "@/features/bandwidth/bandwidth.queries"
import { useBandwidthMonitors } from "@/features/bandwidth/monitor.queries"
import { useRuntimeStatus } from "@/features/monitoring/monitoring.queries"
import type { Device } from "@/lib/wails/types"
import { BulkProgress } from "./DeviceBulkActions"
import { DeviceDetails } from "./DeviceDetails"
import { defaultDevicePreferences, type DevicePreferences, isControlEligible } from "./device-list"
import { DeviceTable } from "./DeviceTable"
import { DeviceToolbar } from "./DeviceToolbar"
import { useDevices } from "./devices.queries"

export function DevicesView() {
  const { data: devices = [], isLoading, error, refetch } = useDevices()
  const { data: bandwidthLimits = [] } = useBandwidthLimits()
  const { data: runtimeStatus } = useRuntimeStatus()
  const { data: bandwidthMonitors = [] } = useBandwidthMonitors(Boolean(runtimeStatus?.BandwidthMonitoringAvailable && runtimeStatus?.Running))
  const clearBandwidth = useClearBandwidthLimits()
  const [preferences, setPreferences] = useState<DevicePreferences>(defaultDevicePreferences)
  const [detailsMAC, setDetailsMAC] = useState("")
  const [checkedMACs, setCheckedMACs] = useState<Set<string>>(() => new Set())
  const drawerTrigger = useRef<HTMLElement | null>(null)
  const restoreAll = useRestoreAllControls()
  const disconnectSelected = useDisconnectSelectedDevices()
  const filtered =
    preferences.query !== "" ||
    preferences.presence !== defaultDevicePreferences.presence ||
    preferences.role !== defaultDevicePreferences.role ||
    preferences.sortBy !== defaultDevicePreferences.sortBy ||
    preferences.descending
  const controlledCount = devices.filter((device) => device.controlState !== "").length
  const bandwidthByMAC = useMemo(
    () => new Map(bandwidthLimits.map((limit) => [limit.mac.toLowerCase(), limit])),
    [bandwidthLimits],
  )
  const bandwidthBlockedMACs = useMemo(
    () => new Set([...bandwidthByMAC.keys(), ...bandwidthMonitors.map((target) => target.mac.toLowerCase())]),
    [bandwidthByMAC, bandwidthMonitors],
  )
  const visible = useMemo(() => filterAndSortDevices(devices, preferences), [devices, preferences])
  const selectedTargets = devices
    .filter(
      (device) =>
        checkedMACs.has(device.mac) && isControlEligible(device) && !bandwidthBlockedMACs.has(device.mac.toLowerCase()),
    )
    .map(({ ip, mac }) => ({ ip, mac }))

  useEffect(() => {
    const eligibleMACs = new Set(
      devices
        .filter((device) => isControlEligible(device) && !bandwidthBlockedMACs.has(device.mac.toLowerCase()))
        .map((device) => device.mac),
    )
    setCheckedMACs((current) => {
      const next = new Set([...current].filter((mac) => eligibleMACs.has(mac)))
      return next.size === current.size ? current : next
    })
  }, [devices, bandwidthBlockedMACs])

  const setChecked = (mac: string, checked: boolean) =>
    setCheckedMACs((current) => {
      const next = new Set(current)
      if (checked) next.add(mac)
      else next.delete(mac)
      return next
    })
  const setVisibleChecked = (checked: boolean) =>
    setCheckedMACs((current) => {
      const next = new Set(current)
      for (const device of visible.filter(
        (candidate) => isControlEligible(candidate) && !bandwidthBlockedMACs.has(candidate.mac.toLowerCase()),
      )) {
        if (checked) next.add(device.mac)
        else next.delete(device.mac)
      }
      return next
    })
  const selected = devices.find((device) => device.mac === detailsMAC)
  const closeDetails = () => {
    setDetailsMAC("")
    window.requestAnimationFrame(() => drawerTrigger.current?.focus())
  }

  return (
    <>
      <MonitoringOverview />
      <Card className="overflow-hidden bg-card/60">
        <DeviceToolbar
          visibleCount={visible.length}
          totalCount={devices.length}
          selectedCount={selectedTargets.length}
          controlledCount={controlledCount}
          limitedCount={bandwidthLimits.length}
          disconnectPending={disconnectSelected.isPending}
          restorePending={restoreAll.isPending}
          clearLimitsPending={clearBandwidth.isPending}
          preferences={preferences}
          onPreferencesChange={setPreferences}
          onDisconnect={() =>
            disconnectSelected.mutate(selectedTargets, { onSuccess: () => setCheckedMACs(new Set()) })
          }
          onRestore={() => restoreAll.mutate()}
          onClearLimits={() => clearBandwidth.mutate(undefined)}
        />
        <CardContent className="p-0">
          {(disconnectSelected.isPending || restoreAll.isPending) && (
            <BulkProgress
              count={disconnectSelected.isPending ? selectedTargets.length : controlledCount}
              operation={disconnectSelected.isPending ? "Disconnecting selected devices" : "Restoring devices"}
            />
          )}
          {error ? (
            <div className="p-4 sm:p-8">
              <QueryError error={error} retry={() => void refetch()} title="Could not load devices" />
            </div>
          ) : isLoading ? (
            <div className="p-12 text-center text-sm text-muted-foreground">Loading devices…</div>
          ) : visible.length ? (
            <DeviceTable
              devices={visible}
              bandwidthByMAC={bandwidthByMAC}
              bandwidthBlockedMACs={bandwidthBlockedMACs}
              checkedMACs={checkedMACs}
              onCheckedChange={setChecked}
              onCheckVisible={setVisibleChecked}
              onOpen={(device, trigger) => {
                drawerTrigger.current = trigger
                setDetailsMAC(device.mac)
              }}
            />
          ) : (
            <div className="p-16 text-center">
              <h3 className="text-sm font-medium">No devices match these filters</h3>
              <p className="mt-1 text-xs text-muted-foreground">Adjust or clear the filters to see more hosts.</p>
              {filtered && (
                <Button
                  className="mt-4"
                  variant="outline"
                  size="sm"
                  onClick={() => setPreferences(defaultDevicePreferences)}
                >
                  Clear filters
                </Button>
              )}
            </div>
          )}
        </CardContent>
      </Card>
      <DeviceDetails
        device={selected}
        bandwidthLimit={selected ? bandwidthByMAC.get(selected.mac.toLowerCase()) : undefined}
        bandwidthAvailable={Boolean(runtimeStatus?.BandwidthAvailable)}
        bandwidthMonitoringAvailable={Boolean(runtimeStatus?.BandwidthMonitoringAvailable)}
        bandwidthMonitored={Boolean(selected && bandwidthMonitors.some((target) => target.mac.toLowerCase() === selected.mac.toLowerCase()))}
        onClose={closeDetails}
      />
    </>
  )
}

function filterAndSortDevices(devices: Device[], preferences: DevicePreferences) {
  return devices
    .filter((device) =>
      `${device.name} ${device.ip} ${device.mac} ${device.vendor} ${device.type}`
        .toLowerCase()
        .includes(preferences.query.toLowerCase()),
    )
    .filter((device) => preferences.presence === "all" || (preferences.presence === "online") === device.online)
    .filter((device) => preferences.role === "all" || device.role === preferences.role)
    .sort((left, right) => {
      const leftValue = preferences.sortBy === "lastSeen" ? new Date(left.lastSeen).getTime() : left[preferences.sortBy]
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
    })
}
