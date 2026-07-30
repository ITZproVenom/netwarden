import { useEffect, useState } from "react"
import { Ban, Copy, LoaderCircle, RadioTower, RotateCcw } from "lucide-react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
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
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { formatDate } from "@/lib/format"
import { copyText } from "@/lib/wails/clipboard"
import type { Device } from "@/lib/wails/types"
import type { BandwidthLimit } from "@/lib/wails/types"
import { BandwidthSection } from "@/features/bandwidth/BandwidthSection"
import { useSetNickname } from "./devices.queries"
import {
  useControlAudit,
  useDisconnectDevice,
  useRestoreControl,
  useStartContinuousControl,
  useStopContinuousControl,
} from "@/features/control/control.queries"

function Detail({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-5 py-2 text-xs">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={mono ? "font-mono" : ""}>{value}</dd>
    </div>
  )
}
function CopyDetail({ label, value }: { label: string; value: string }) {
  const copy = async () => {
    try {
      await copyText(value)
      toast.success(`${label} copied`)
    } catch {
      toast.error(`Could not copy ${label.toLowerCase()}`)
    }
  }
  return (
    <div className="flex items-center justify-between gap-5 py-1 text-xs">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="flex items-center gap-1 font-mono">
        {value}
        <Button variant="ghost" size="icon-xs" aria-label={`Copy ${label.toLowerCase()}`} onClick={copy}>
          <Copy />
        </Button>
      </dd>
    </div>
  )
}

export function DeviceDetails({
  device,
  bandwidthLimit,
  bandwidthAvailable,
  onClose,
}: {
  device?: Device
  bandwidthLimit?: BandwidthLimit
  bandwidthAvailable: boolean
  onClose: () => void
}) {
  const [nickname, setNickname] = useState("")
  const mutation = useSetNickname()
  useEffect(() => setNickname(device && device.name !== device.ip ? device.name : ""), [device])
  return (
    <Sheet
      open={Boolean(device)}
      onOpenChange={(open) => {
        if (!open) onClose()
      }}
    >
      <SheetContent className="w-[420px] sm:max-w-[420px]">
        <SheetHeader className="border-b p-6">
          <div className="flex items-center gap-3">
            <span
              className={`size-3 rounded-full ${device?.online ? "bg-primary shadow-[0_0_12px_var(--primary)]" : "bg-muted-foreground"}`}
            />
            <div>
              <SheetTitle>{device?.name}</SheetTitle>
              <SheetDescription>{device?.role}</SheetDescription>
            </div>
          </div>
        </SheetHeader>
        {device && (
          <div className="overflow-y-auto px-6">
            <section className="py-6">
              <h4 className="mb-3 text-xs font-semibold">Identity</h4>
              <dl>
                <CopyDetail label="IP address" value={device.ip} />
                <CopyDetail label="MAC address" value={device.mac} />
                <Detail label="Vendor" value={device.vendor || "Unknown"} />
                <Detail label="Type" value={device.type || "Unknown"} />
                <div className="flex justify-between py-2 text-xs">
                  <dt className="text-muted-foreground">Status</dt>
                  <dd>
                    <Badge variant={device.online ? "default" : "secondary"}>
                      {device.online ? "Online" : "Offline"}
                    </Badge>
                  </dd>
                </div>
              </dl>
            </section>
            <Separator />
            <ControlSection device={device} bandwidthLimited={Boolean(bandwidthLimit)} />
            <Separator />
            <BandwidthSection device={device} limit={bandwidthLimit} available={bandwidthAvailable} />
            <Separator />
            <section className="py-6">
              <h4 className="mb-3 text-xs font-semibold">Observation history</h4>
              <dl>
                <Detail label="First seen" value={formatDate(device.firstSeen)} />
                <Detail label="Last seen" value={formatDate(device.lastSeen)} />
              </dl>
            </section>
            <Separator />
            <section className="space-y-3 py-6">
              <div>
                <h4 className="text-xs font-semibold">Nickname</h4>
                <p className="mt-1 text-xs text-muted-foreground">Use a recognizable name for this device.</p>
              </div>
              <Label htmlFor="nickname">Device name</Label>
              <Input
                id="nickname"
                maxLength={64}
                placeholder={device.ip}
                value={nickname}
                onChange={(event) => setNickname(event.target.value)}
              />
              <Button
                disabled={mutation.isPending || nickname.trim() === (device.name === device.ip ? "" : device.name)}
                onClick={() => mutation.mutate({ mac: device.mac, nickname: nickname.trim() })}
              >
                Save nickname
              </Button>
            </section>
          </div>
        )}
      </SheetContent>
    </Sheet>
  )
}

function ControlSection({ device, bandwidthLimited }: { device: Device; bandwidthLimited: boolean }) {
  const eligible = device.online && device.role === "Device" && !bandwidthLimited
  const disconnect = useDisconnectDevice()
  const continuous = useStartContinuousControl()
  const restore = useRestoreControl()
  const stop = useStopContinuousControl()
  const { data: audit = [] } = useControlAudit()
  const recent = audit
    .filter((event) => event.targets.some((target) => target.toLowerCase().includes(device.mac.toLowerCase())))
    .slice(0, 3)
  const pending = disconnect.isPending || continuous.isPending || restore.isPending || stop.isPending
  const recovering = restore.isPending || stop.isPending || device.controlState === "restoring"
  const controlled =
    device.controlState === "active" ||
    device.controlState === "continuous" ||
    device.controlState === "restoring" ||
    device.controlState === "failed"
  const label =
    device.controlState === "continuous"
      ? "Continuous"
      : device.controlState === "restoring"
        ? "Restoring"
        : device.controlState === "failed"
          ? "Recovery failed"
          : device.controlState === "active"
            ? "Disconnected"
            : eligible
              ? "Available"
              : bandwidthLimited
                ? "Bandwidth limited"
                : device.role !== "Device"
                  ? "Protected"
                  : "Offline"
  return (
    <section className="space-y-3 py-6">
      <div className="flex items-center justify-between">
        <h4 className="text-xs font-semibold">Device control</h4>
        <Badge variant={controlled ? "destructive" : eligible ? "outline" : "secondary"}>
          {(pending || device.controlState === "restoring") && <LoaderCircle className="animate-spin" />}
          {label}
        </Badge>
      </div>
      <div className="flex flex-wrap gap-2">
        {controlled ? (
          <>
            <ControlConfirmation
              title="Restore device"
              description={`Restore normal network access for ${device.name}?`}
              disabled={recovering}
              onConfirm={() => restore.mutate({ ip: device.ip, mac: device.mac })}
            >
              <RotateCcw />
              Restore
            </ControlConfirmation>
            {device.controlState === "continuous" && (
              <ControlConfirmation
                title="Stop continuous control"
                description={`Stop continuous control and restore ${device.name}?`}
                disabled={recovering}
                onConfirm={() => stop.mutate({ ip: device.ip, mac: device.mac })}
              >
                <RadioTower />
                Stop continuous
              </ControlConfirmation>
            )}
          </>
        ) : (
          <>
            <ControlConfirmation
              title="Disconnect device"
              description={`Disconnect ${device.name} from the network?`}
              disabled={!eligible || pending}
              onConfirm={() => disconnect.mutate({ ip: device.ip, mac: device.mac })}
            >
              <Ban />
              Disconnect
            </ControlConfirmation>
            <ControlConfirmation
              title="Start continuous control"
              description={`Continuously prevent ${device.name} from reconnecting until explicitly restored?`}
              disabled={!eligible || pending}
              onConfirm={() => continuous.mutate({ ip: device.ip, mac: device.mac })}
            >
              <RadioTower />
              Continuous
            </ControlConfirmation>
          </>
        )}
      </div>
      {recent.length > 0 && (
        <div className="rounded-lg border bg-background/30 p-3">
          <p className="mb-2 text-[10px] font-semibold tracking-wide text-muted-foreground uppercase">
            Recent control activity
          </p>
          {recent.map((event, index) => (
            <div key={`${event.at}-${index}`} className="flex justify-between gap-3 py-1 text-[10px]">
              <span>{event.operation.replaceAll("_", " ")}</span>
              <span className="text-muted-foreground">{event.outcome.replaceAll("_", " ")}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  )
}

function ControlConfirmation({
  title,
  description,
  disabled,
  onConfirm,
  children,
}: {
  title: string
  description: string
  disabled: boolean
  onConfirm: () => void
  children: React.ReactNode
}) {
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>
        <Button variant="outline" size="sm" disabled={disabled}>
          {children}
        </Button>
      </AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}?</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction onClick={onConfirm}>Confirm</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
