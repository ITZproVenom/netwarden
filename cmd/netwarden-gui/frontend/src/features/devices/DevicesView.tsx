import { useMemo, useState } from "react"
import { ChevronRight, Search } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import type { Device } from "@/lib/wails/types"
import { useDevices } from "./devices.queries"
import { DeviceDetails } from "./DeviceDetails"

export function DevicesView() {
  const { data: devices = [], isLoading, error } = useDevices()
  const [query, setQuery] = useState("")
  const [selectedMAC, setSelectedMAC] = useState("")
  const visible = useMemo(() => devices.filter(device => `${device.name} ${device.ip} ${device.mac} ${device.vendor}`.toLowerCase().includes(query.toLowerCase())), [devices, query])
  const selected = devices.find(device => device.mac === selectedMAC)
  return <><Card className="overflow-hidden bg-card/60"><CardHeader className="flex-row items-center justify-between border-b"><div><CardTitle>Devices</CardTitle><CardDescription>Live and previously observed hosts</CardDescription></div><div className="relative"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" /><Input className="w-64 pl-9" placeholder="Search devices…" value={query} onChange={event => setQuery(event.target.value)} /></div></CardHeader><CardContent className="p-0">{error ? <div className="p-12 text-center text-sm text-destructive">{String(error)}</div> : isLoading ? <div className="p-12 text-center text-sm text-muted-foreground">Loading devices…</div> : visible.length ? <Table><TableHeader><TableRow><TableHead>Device</TableHead><TableHead>Address</TableHead><TableHead>Vendor</TableHead><TableHead>Role</TableHead><TableHead>Status</TableHead><TableHead /></TableRow></TableHeader><TableBody>{visible.map(device => <DeviceRow key={device.mac} device={device} onClick={() => setSelectedMAC(device.mac)} />)}</TableBody></Table> : <div className="p-16 text-center"><h3 className="text-sm font-medium">No devices to show</h3><p className="mt-1 text-xs text-muted-foreground">Start monitoring to discover hosts on this network.</p></div>}</CardContent></Card><DeviceDetails device={selected} onClose={() => setSelectedMAC("")} /></>
}

function DeviceRow({ device, onClick }: { device: Device; onClick: () => void }) { return <TableRow className="cursor-pointer" onClick={onClick}><TableCell><div className="flex items-center gap-3"><span className={`size-2 rounded-full ${device.online ? "bg-primary shadow-[0_0_8px_var(--primary)]" : "bg-muted-foreground/60"}`} /><div><p className="font-medium">{device.name || device.ip}</p><p className="font-mono text-[10px] text-muted-foreground">{device.mac}</p></div></div></TableCell><TableCell>{device.ip}</TableCell><TableCell className="text-muted-foreground">{device.vendor || "Unknown"}</TableCell><TableCell><Badge variant="outline">{device.role}</Badge></TableCell><TableCell><Badge variant={device.online ? "default" : "secondary"}>{device.online ? "Online" : "Offline"}</Badge></TableCell><TableCell><ChevronRight className="size-4 text-muted-foreground" /></TableCell></TableRow> }
