import { useEffect, useState } from "react"
import { Router } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useBootstrap, useRuntimeStatus } from "@/features/monitoring/monitoring.queries"
import { useSetGatewayMAC } from "./settings.queries"

export function SettingsView() {
  const { data: bootstrap } = useBootstrap()
  const { data: status } = useRuntimeStatus()
  const mutation = useSetGatewayMAC()
  const [gatewayMAC, setGatewayMAC] = useState("")
  useEffect(() => setGatewayMAC(bootstrap?.gatewayMAC || ""), [bootstrap?.gatewayMAC])
  const running = Boolean(status?.Running || status?.Rebuilding)
  const saved = bootstrap?.gatewayMAC || ""
  return <Card className="bg-card/60"><CardHeader className="border-b"><CardTitle>Settings</CardTitle><CardDescription>Configure how NetWarden identifies this network</CardDescription></CardHeader><CardContent className="grid grid-cols-2 gap-16 py-8"><div><div className="flex items-center gap-3"><span className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary"><Router className="size-4" /></span><h3 className="text-sm font-medium">Trusted gateway identity</h3></div><p className="mt-4 max-w-xl text-xs leading-6 text-muted-foreground">Pin the hardware address of your router. NetWarden reports gateway claims from any different MAC address. Leave this empty to learn the gateway identity when monitoring starts.</p>{running && <Alert className="mt-5"><AlertTitle>Monitoring is active</AlertTitle><AlertDescription>Stop monitoring before changing this setting.</AlertDescription></Alert>}</div><div className="space-y-3"><Label htmlFor="gateway-mac">Gateway MAC address</Label><Input id="gateway-mac" className="font-mono" spellCheck={false} placeholder="00:11:22:33:44:55" value={gatewayMAC} disabled={running} onChange={event => setGatewayMAC(event.target.value)} /><p className="text-xs text-muted-foreground">{saved ? `Pinned to ${saved}` : "Automatically learned when monitoring starts"}</p><div className="flex gap-2 pt-2"><Button disabled={running || mutation.isPending || gatewayMAC.trim().toLowerCase() === saved.toLowerCase()} onClick={() => mutation.mutate(gatewayMAC.trim())}>Save baseline</Button>{saved && <Button variant="outline" disabled={running || mutation.isPending} onClick={() => mutation.mutate("")}>Use automatic</Button>}</div></div></CardContent></Card>
}
