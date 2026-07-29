import { ArrowDownAZ, Search, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { DisconnectSelected, RestoreAll } from "./DeviceBulkActions"
import { defaultDevicePreferences, type DevicePreferences, type DeviceSortKey } from "./device-list"

export function DeviceToolbar({
  visibleCount,
  totalCount,
  selectedCount,
  controlledCount,
  disconnectPending,
  restorePending,
  preferences,
  onPreferencesChange,
  onDisconnect,
  onRestore,
}: {
  visibleCount: number
  totalCount: number
  selectedCount: number
  controlledCount: number
  disconnectPending: boolean
  restorePending: boolean
  preferences: DevicePreferences
  onPreferencesChange: (preferences: DevicePreferences) => void
  onDisconnect: () => void
  onRestore: () => void
}) {
  const update = <K extends keyof DevicePreferences>(key: K, value: DevicePreferences[K]) =>
    onPreferencesChange({ ...preferences, [key]: value })
  const filtered =
    preferences.query !== "" ||
    preferences.presence !== defaultDevicePreferences.presence ||
    preferences.role !== defaultDevicePreferences.role ||
    preferences.sortBy !== defaultDevicePreferences.sortBy ||
    preferences.descending
  return (
    <CardHeader className="gap-4 border-b">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <CardTitle>Devices</CardTitle>
          <CardDescription>
            {visibleCount} of {totalCount} known hosts
          </CardDescription>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
          {selectedCount > 0 && (
            <DisconnectSelected count={selectedCount} pending={disconnectPending} disconnect={onDisconnect} />
          )}
          {controlledCount > 0 && <RestoreAll count={controlledCount} pending={restorePending} restore={onRestore} />}
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
          onChange={(event) => update("sortBy", event.target.value as DeviceSortKey)}
        >
          <NativeSelectOption value="name">Sort by name</NativeSelectOption>
          <NativeSelectOption value="ip">Sort by IP address</NativeSelectOption>
          <NativeSelectOption value="vendor">Sort by vendor</NativeSelectOption>
          <NativeSelectOption value="type">Sort by type</NativeSelectOption>
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
          <Button variant="ghost" size="sm" onClick={() => onPreferencesChange(defaultDevicePreferences)}>
            <X />
            Clear filters
          </Button>
        )}
      </div>
    </CardHeader>
  )
}
