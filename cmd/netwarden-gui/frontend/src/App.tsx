import { useState } from "react"
import { AppShell, type AppView } from "@/app/AppShell"
import { MonitoringOverview } from "@/features/monitoring/MonitoringOverview"
import { DevicesView } from "@/features/devices/DevicesView"
import { IntegrityView } from "@/features/integrity/IntegrityView"
import { SettingsView } from "@/features/settings/SettingsView"

export default function App() {
  const [view, setView] = useState<AppView>("devices")

  return (
    <AppShell view={view} onViewChange={setView}>
      <MonitoringOverview />
      {view === "devices" && <DevicesView />}
      {view === "integrity" && <IntegrityView />}
      {view === "settings" && <SettingsView />}
    </AppShell>
  )
}
