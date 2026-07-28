import { useMemo, useState } from "react"
import { ArrowDownAZ, ChevronRight, Search } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import type { Device } from "@/lib/wails/types"
import { formatDate } from "@/lib/format"
import { useDevices } from "./devices.queries"
import { DeviceDetails } from "./DeviceDetails"

export function DevicesView() {
  const { data: devices = [], isLoading, error } = useDevices()
  const [query, setQuery] = useState("")
  const [selectedMAC, setSelectedMAC] = useState("")
  const [presence, setPresence] = useState("all")
  const [role, setRole] = useState("all")
  const [sortBy, setSortBy] = useState<"name" | "ip" | "vendor" | "role" | "lastSeen">("name")
  const [descending, setDescending] = useState(false)
  const visible = useMemo(() => devices
    .filter(device => `${device.name} ${device.ip} ${device.mac} ${device.vendor}`.toLowerCase().includes(query.toLowerCase()))
    .filter(device => presence === "all" || (presence === "online") === device.online)
    .filter(device => role === "all" || device.role === role)
    .sort((left, right) => {
      const leftValue = sortBy === "lastSeen" ? new Date(left.lastSeen).getTime() : left[sortBy]
      const rightValue = sortBy === "lastSeen" ? new Date(right.lastSeen).getTime() : right[sortBy]
      const result = typeof leftValue === "number" ? leftValue - Number(rightValue) : String(leftValue).localeCompare(String(rightValue), undefined, { numeric: sortBy === "ip", sensitivity: "base" })
      return descending ? -result : result
    }), [devices, query, presence, role, sortBy, descending])
  const selected = devices.find(device => device.mac === selectedMAC)
  return <><Card className="overflow-hidden bg-card/60"><CardHeader className="border-b"><div className="flex items-center justify-between"><div><CardTitle>Devices</CardTitle><CardDescription>{visible.length} of {devices.length} known hosts</CardDescription></div><div className="relative"><Search className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" /><Input className="w-64 pl-9" placeholder="Search devices…" value={query} onChange={event => setQuery(event.target.value)} /></div></div><div className="mt-3 flex gap-2"><NativeSelect aria-label="Filter by status" value={presence} onChange={event => setPresence(event.target.value)}><NativeSelectOption value="all">All statuses</NativeSelectOption><NativeSelectOption value="online">Online</NativeSelectOption><NativeSelectOption value="offline">Offline</NativeSelectOption></NativeSelect><NativeSelect aria-label="Filter by role" value={role} onChange={event => setRole(event.target.value)}><NativeSelectOption value="all">All roles</NativeSelectOption><NativeSelectOption value="Device">Devices</NativeSelectOption><NativeSelectOption value="Gateway">Gateway</NativeSelectOption><NativeSelectOption value="This device">This device</NativeSelectOption></NativeSelect><NativeSelect aria-label="Sort devices" value={sortBy} onChange={event => setSortBy(event.target.value as typeof sortBy)}><NativeSelectOption value="name">Sort by name</NativeSelectOption><NativeSelectOption value="ip">Sort by IP address</NativeSelectOption><NativeSelectOption value="vendor">Sort by vendor</NativeSelectOption><NativeSelectOption value="role">Sort by role</NativeSelectOption><NativeSelectOption value="lastSeen">Sort by last seen</NativeSelectOption></NativeSelect><Button variant="outline" size="icon" aria-label={descending ? "Sort ascending" : "Sort descending"} onClick={() => setDescending(value => !value)}><ArrowDownAZ className={descending ? "rotate-180" : ""} /></Button></div></CardHeader><CardContent className="p-0">{error ? <div className="p-12 text-center text-sm text-destructive">{String(error)}</div> : isLoading ? <div className="p-12 text-center text-sm text-muted-foreground">Loading devices…</div> : visible.length ? <Table><TableHeader><TableRow><TableHead>Device</TableHead><TableHead>Address</TableHead><TableHead>Vendor</TableHead><TableHead>Role</TableHead><TableHead>Status</TableHead><TableHead>Last seen</TableHead><TableHead /></TableRow></TableHeader><TableBody>{visible.map(device => <DeviceRow key={device.mac} device={device} onClick={() => setSelectedMAC(device.mac)} />)}</TableBody></Table> : <div className="p-16 text-center"><h3 className="text-sm font-medium">No devices match these filters</h3><p className="mt-1 text-xs text-muted-foreground">Adjust the search or filters to see more hosts.</p></div>}</CardContent></Card><DeviceDetails device={selected} onClose={() => setSelectedMAC("")} /></>
}

function DeviceRow({ device, onClick }: { device: Device; onClick: () => void }) { return <TableRow className="cursor-pointer" onClick={onClick}><TableCell><div className="flex items-center gap-3"><span className={`size-2 rounded-full ${device.online ? "bg-primary shadow-[0_0_8px_var(--primary)]" : "bg-muted-foreground/60"}`} /><div><p className="font-medium">{device.name || device.ip}</p><p className="font-mono text-[10px] text-muted-foreground">{device.mac}</p></div></div></TableCell><TableCell>{device.ip}</TableCell><TableCell className="max-w-48 truncate text-muted-foreground" title={device.vendor}>{device.vendor || "Unknown"}</TableCell><TableCell><Badge variant="outline">{device.role}</Badge></TableCell><TableCell><Badge variant={device.online ? "default" : "secondary"}>{device.online ? "Online" : "Offline"}</Badge></TableCell><TableCell className="text-xs text-muted-foreground">{formatDate(device.lastSeen)}</TableCell><TableCell><ChevronRight className="size-4 text-muted-foreground" /></TableCell></TableRow> }
