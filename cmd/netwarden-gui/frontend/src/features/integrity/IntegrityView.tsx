import { ShieldAlert, ShieldCheck } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { QueryError } from "@/components/QueryError"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { formatDate } from "@/lib/format"
import { useConflicts, useIPv6Network } from "./integrity.queries"

export function IntegrityView() {
  const { data: conflicts = [], isLoading, error, refetch } = useConflicts()
  const { data: ipv6 } = useIPv6Network()
  const active = conflicts.filter((conflict) => conflict.active).length
  return (
    <div className="space-y-5">
    <Card className="overflow-hidden bg-card/60">
      <CardHeader className="flex-row items-center justify-between border-b">
        <div>
          <CardTitle>Gateway security</CardTitle>
          <CardDescription>Detect devices attempting to impersonate your router</CardDescription>
        </div>
        <Badge variant={active ? "destructive" : "outline"}>
          {active ? `${active} active warning${active === 1 ? "" : "s"}` : "No active warnings"}
        </Badge>
      </CardHeader>
      <CardContent className="p-0">
        {active > 0 && (
          <div className="p-5">
            <Alert variant="destructive">
              <ShieldAlert />
              <AlertTitle>Unexpected gateway identity detected</AlertTitle>
              <AlertDescription>
                A device has claimed your gateway address using a different MAC address. Verify your router and local
                network.
              </AlertDescription>
            </Alert>
          </div>
        )}
        {error ? (
          <div className="p-4 sm:p-8">
            <QueryError error={error} retry={() => void refetch()} title="Could not load gateway security history" />
          </div>
        ) : isLoading ? (
          <div className="p-12 text-center text-sm text-muted-foreground">Loading gateway security history…</div>
        ) : conflicts.length ? (
          <div className="overflow-x-auto">
            <Table className="min-w-[760px]">
              <TableHeader>
                <TableRow>
                  <TableHead>Claimed identity</TableHead>
                  <TableHead>Gateway</TableHead>
                  <TableHead>First seen</TableHead>
                  <TableHead>Last seen</TableHead>
                  <TableHead>Observations</TableHead>
                  <TableHead>State</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {conflicts.map((conflict) => (
                  <TableRow key={`${conflict.claimedMAC}-${conflict.firstSeen}`}>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        {conflict.active ? (
                          <ShieldAlert className="size-4 text-destructive" />
                        ) : (
                          <ShieldCheck className="size-4 text-primary" />
                        )}
                        <div>
                          <p className="font-mono text-xs">{conflict.claimedMAC}</p>
                          <p className="text-[10px] text-muted-foreground">Unexpected gateway MAC</p>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>{conflict.gatewayIP}</TableCell>
                    <TableCell>{formatDate(conflict.firstSeen)}</TableCell>
                    <TableCell>{formatDate(conflict.lastSeen)}</TableCell>
                    <TableCell>{conflict.count}</TableCell>
                    <TableCell>
                      <Badge variant={conflict.active ? "destructive" : "secondary"}>
                        {conflict.active ? "Active" : "Restored"}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <div className="p-16 text-center">
            <ShieldCheck className="mx-auto size-9 text-primary" />
            <h3 className="mt-3 text-sm font-medium">No gateway conflicts observed</h3>
            <p className="mt-1 text-xs text-muted-foreground">Unexpected gateway identity claims will appear here.</p>
          </div>
        )}
      </CardContent>
    </Card>
    <Card className="overflow-hidden bg-card/60">
      <CardHeader className="flex-row items-center justify-between border-b">
        <div>
          <CardTitle>IPv6 router integrity</CardTitle>
          <CardDescription>Router Advertisements, prefixes, lifetimes, and identity claims</CardDescription>
        </div>
        <Badge variant={ipv6?.conflictCount ? "destructive" : "outline"}>
          {ipv6?.conflictCount ? `${ipv6.conflictCount} active warning${ipv6.conflictCount === 1 ? "" : "s"}` : "No active warnings"}
        </Badge>
      </CardHeader>
      <CardContent className="p-0">
        {ipv6?.conflicts.some((conflict) => conflict.active) && (
          <div className="p-5">
            <Alert variant="destructive">
              <ShieldAlert />
              <AlertTitle>Unexpected IPv6 router identity detected</AlertTitle>
              <AlertDescription>A Router Advertisement used a different MAC address than the learned identity.</AlertDescription>
            </Alert>
          </div>
        )}
        {ipv6?.routers.length ? (
          <div className="overflow-x-auto">
            <Table className="min-w-[820px]">
              <TableHeader>
                <TableRow>
                  <TableHead>Router</TableHead>
                  <TableHead>Identity</TableHead>
                  <TableHead>Preference</TableHead>
                  <TableHead>Advertised prefixes</TableHead>
                  <TableHead>Expires</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ipv6.routers.map((router) => (
                  <TableRow key={`${router.ip}-${router.mac}`}>
                    <TableCell>
                      <p className="font-mono text-xs">{router.ip}</p>
                      {ipv6.defaultRouter?.ip === router.ip && <Badge className="mt-1" variant="outline">Selected</Badge>}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{router.mac}</TableCell>
                    <TableCell>{router.preference > 0 ? "High" : router.preference < 0 ? "Low" : "Medium"}</TableCell>
                    <TableCell>
                      {router.prefixes.length ? router.prefixes.map((prefix) => (
                        <div key={prefix.prefix} className="mb-1">
                          <p className="font-mono text-xs">{prefix.prefix}</p>
                          <p className="text-[10px] text-muted-foreground">
                            {prefix.onLink ? "On-link" : "Off-link"} · {prefix.autonomous ? "SLAAC" : "Managed"} · preferred until {formatDate(prefix.preferredUntil)} · valid until {formatDate(prefix.validUntil)}
                          </p>
                        </div>
                      )) : <span className="text-muted-foreground">None</span>}
                    </TableCell>
                    <TableCell>{formatDate(router.expiresAt)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        ) : (
          <div className="p-12 text-center">
            <ShieldCheck className="mx-auto size-9 text-primary" />
            <h3 className="mt-3 text-sm font-medium">No active IPv6 router observed</h3>
            <p className="mt-1 text-xs text-muted-foreground">Validated Router Advertisements will appear here.</p>
          </div>
        )}
        {ipv6?.conflicts.length ? (
          <div className="border-t p-5">
            <h4 className="mb-3 text-xs font-semibold">IPv6 identity history</h4>
            {ipv6.conflicts.map((conflict) => (
              <div key={`${conflict.routerIP}-${conflict.claimedMAC}`} className="flex flex-wrap justify-between gap-3 border-b py-2 text-xs last:border-0">
                <span className="font-mono">{conflict.routerIP} · {conflict.claimedMAC}</span>
                <span className="text-muted-foreground">expected {conflict.expectedMAC} · {conflict.count} observation{conflict.count === 1 ? "" : "s"}</span>
                <Badge variant={conflict.active ? "destructive" : "secondary"}>{conflict.active ? "Active" : "Restored"}</Badge>
              </div>
            ))}
          </div>
        ) : null}
        {ipv6?.trustedIdentities.length ? (
          <div className="border-t p-5">
            <h4 className="mb-3 text-xs font-semibold">Learned router identities</h4>
            <div className="flex flex-wrap gap-2">
              {ipv6.trustedIdentities.map((identity) => (
                <Badge key={`${identity.routerIP}-${identity.mac}`} variant="outline" className="font-mono font-normal">
                  {identity.routerIP} · {identity.mac}
                </Badge>
              ))}
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
    </div>
  )
}
