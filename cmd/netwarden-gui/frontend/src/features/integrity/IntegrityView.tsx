import { ShieldAlert, ShieldCheck } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { QueryError } from "@/components/QueryError"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { formatDate } from "@/lib/format"
import { useConflicts } from "./integrity.queries"

export function IntegrityView() {
  const { data: conflicts = [], isLoading, error, refetch } = useConflicts()
  const active = conflicts.filter((conflict) => conflict.active).length
  return (
    <Card className="overflow-hidden bg-card/60">
      <CardHeader className="flex-row items-center justify-between border-b">
        <div>
          <CardTitle>Gateway integrity</CardTitle>
          <CardDescription>Claims that differed from the trusted gateway identity</CardDescription>
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
            <QueryError error={error} retry={() => void refetch()} title="Could not load integrity history" />
          </div>
        ) : isLoading ? (
          <div className="p-12 text-center text-sm text-muted-foreground">Loading integrity history…</div>
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
  )
}
