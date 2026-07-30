import { useEffect, useState } from "react"
import { Bell } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import type { NotificationSettings } from "@/lib/wails/types"
import { useUnsavedChanges } from "@/app/unsaved-changes"
import { useNotificationSettings, useSetNotificationSettings } from "./settings.queries"

const defaults: NotificationSettings = {
  enabled: true,
  newDevices: true,
  knownDevices: true,
  deviceOffline: false,
  suspiciousDevices: true,
}

export function NotificationSettingsCard() {
  const { data } = useNotificationSettings()
  const mutation = useSetNotificationSettings()
  const [form, setForm] = useState(defaults)
  useEffect(() => {
    if (data) setForm(data)
  }, [data])
  const changed = Boolean(data && JSON.stringify(form) !== JSON.stringify(data))
  useUnsavedChanges("notification-settings", changed)

  const toggle = (key: keyof NotificationSettings, checked: boolean) =>
    setForm((current) => ({ ...current, [key]: checked }))

  return (
    <Card className="bg-card/60">
      <CardHeader className="border-b">
        <div className="flex items-center gap-3">
          <span className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary">
            <Bell className="size-4" />
          </span>
          <div>
            <CardTitle>Notifications</CardTitle>
            <CardDescription>Choose which network events can send a system notification</CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-6 py-8">
        <NotificationToggle
          label="Allow notifications"
          description="Master control for all NetWarden system notifications. Activity is still recorded when disabled."
          checked={form.enabled}
          onChange={(checked) => toggle("enabled", checked)}
        />
        <div className="grid grid-cols-2 gap-x-16 gap-y-6 border-t pt-6">
          <NotificationToggle
            label="New devices"
            description="Notify when a device is seen on this network for the first time."
            checked={form.newDevices}
            disabled={!form.enabled}
            onChange={(checked) => toggle("newDevices", checked)}
          />
          <NotificationToggle
            label="Known devices return"
            description="Notify when a previously seen device comes back online."
            checked={form.knownDevices}
            disabled={!form.enabled}
            onChange={(checked) => toggle("knownDevices", checked)}
          />
          <NotificationToggle
            label="Known devices leave"
            description="Notify after a known device reaches the configured offline timeout."
            checked={form.deviceOffline}
            disabled={!form.enabled}
            onChange={(checked) => toggle("deviceOffline", checked)}
          />
          <NotificationToggle
            label="Suspicious activity"
            description="Notify about IP conflicts, gateway integrity warnings, and failed control restoration."
            checked={form.suspiciousDevices}
            disabled={!form.enabled}
            onChange={(checked) => toggle("suspiciousDevices", checked)}
          />
        </div>
        <div className="flex justify-end gap-2 border-t pt-5">
          <Button variant="outline" disabled={!changed || mutation.isPending} onClick={() => data && setForm(data)}>
            Reset
          </Button>
          <Button disabled={!changed || mutation.isPending} onClick={() => mutation.mutate(form)}>
            Save notification settings
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}

function NotificationToggle({
  label,
  description,
  checked,
  disabled = false,
  onChange,
}: {
  label: string
  description: string
  checked: boolean
  disabled?: boolean
  onChange: (checked: boolean) => void
}) {
  return (
    <div className="flex items-center justify-between gap-5">
      <div>
        <Label>{label}</Label>
        <p className="mt-1 text-xs text-muted-foreground">{description}</p>
      </div>
      <Switch checked={checked} disabled={disabled} onCheckedChange={onChange} />
    </div>
  )
}
