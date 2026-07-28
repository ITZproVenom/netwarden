import { useEffect, useState } from "react"
import { Copy } from "lucide-react"
import { toast } from "sonner"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Separator } from "@/components/ui/separator"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet"
import { formatDate } from "@/lib/format"
import { copyText } from "@/lib/wails/clipboard"
import type { Device } from "@/lib/wails/types"
import { useSetNickname } from "./devices.queries"

function Detail({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) { return <div className="flex justify-between gap-5 py-2 text-xs"><dt className="text-muted-foreground">{label}</dt><dd className={mono ? "font-mono" : ""}>{value}</dd></div> }
function CopyDetail({ label, value }: { label: string; value: string }) { const copy = async () => { try { await copyText(value); toast.success(`${label} copied`) } catch { toast.error(`Could not copy ${label.toLowerCase()}`) } }; return <div className="flex items-center justify-between gap-5 py-1 text-xs"><dt className="text-muted-foreground">{label}</dt><dd className="flex items-center gap-1 font-mono">{value}<Button variant="ghost" size="icon-xs" aria-label={`Copy ${label.toLowerCase()}`} onClick={copy}><Copy /></Button></dd></div> }

export function DeviceDetails({ device, onClose }: { device?: Device; onClose: () => void }) {
  const [nickname, setNickname] = useState("")
  const mutation = useSetNickname()
  useEffect(() => setNickname(device && device.name !== device.ip ? device.name : ""), [device])
  return <Sheet open={Boolean(device)} onOpenChange={open => { if (!open) onClose() }}><SheetContent className="w-[420px] sm:max-w-[420px]"><SheetHeader className="border-b p-6"><div className="flex items-center gap-3"><span className={`size-3 rounded-full ${device?.online ? "bg-primary shadow-[0_0_12px_var(--primary)]" : "bg-muted-foreground"}`} /><div><SheetTitle>{device?.name}</SheetTitle><SheetDescription>{device?.role}</SheetDescription></div></div></SheetHeader>{device && <div className="overflow-y-auto px-6"><section className="py-6"><h4 className="mb-3 text-xs font-semibold">Identity</h4><dl><CopyDetail label="IP address" value={device.ip} /><CopyDetail label="MAC address" value={device.mac} /><Detail label="Vendor" value={device.vendor || "Unknown"} /><div className="flex justify-between py-2 text-xs"><dt className="text-muted-foreground">Status</dt><dd><Badge variant={device.online ? "default" : "secondary"}>{device.online ? "Online" : "Offline"}</Badge></dd></div></dl></section><Separator /><section className="py-6"><h4 className="mb-3 text-xs font-semibold">Observation history</h4><dl><Detail label="First seen" value={formatDate(device.firstSeen)} /><Detail label="Last seen" value={formatDate(device.lastSeen)} /></dl></section><Separator /><section className="space-y-3 py-6"><div><h4 className="text-xs font-semibold">Nickname</h4><p className="mt-1 text-xs text-muted-foreground">Use a recognizable name for this device.</p></div><Label htmlFor="nickname">Device name</Label><Input id="nickname" maxLength={64} placeholder={device.ip} value={nickname} onChange={event => setNickname(event.target.value)} /><Button disabled={mutation.isPending || nickname.trim() === (device.name === device.ip ? "" : device.name)} onClick={() => mutation.mutate({ mac: device.mac, nickname: nickname.trim() })}>Save nickname</Button></section></div>}</SheetContent></Sheet>
}
