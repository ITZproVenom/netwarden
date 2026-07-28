import { Info, MonitorCog, Palette } from "lucide-react"
import { useTheme } from "next-themes"
import packageInfo from "../../../package.json"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"

export function ApplicationPreferencesCard() {
  const { theme, setTheme } = useTheme()
  return (
    <Card className="bg-card/60">
      <CardHeader className="border-b">
        <div className="flex items-center gap-3">
          <span className="grid size-9 place-items-center rounded-lg bg-primary/10 text-primary">
            <MonitorCog className="size-4" />
          </span>
          <div>
            <CardTitle>Application</CardTitle>
            <CardDescription>Appearance and local application information</CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="grid gap-6 py-6 md:grid-cols-2 md:gap-12">
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Palette className="size-4 text-primary" />
            <Label htmlFor="theme">Appearance</Label>
          </div>
          <NativeSelect
            id="theme"
            className="w-full"
            value={theme || "system"}
            onChange={(event) => setTheme(event.target.value)}
          >
            <NativeSelectOption value="system">Use system appearance</NativeSelectOption>
            <NativeSelectOption value="dark">Dark</NativeSelectOption>
            <NativeSelectOption value="light">Light</NativeSelectOption>
          </NativeSelect>
          <p className="text-xs text-muted-foreground">Your choice is stored on this device.</p>
        </div>
        <div className="rounded-lg border bg-background/30 p-4">
          <div className="flex items-center gap-2">
            <Info className="size-4 text-primary" />
            <p className="text-sm font-medium">NetWarden {packageInfo.version}</p>
          </div>
          <p className="mt-3 text-xs leading-5 text-muted-foreground">
            Local network monitoring and gateway-integrity protection. Configuration, history, audit records, and logs
            remain in the operating system’s application-data directory.
          </p>
        </div>
      </CardContent>
    </Card>
  )
}
