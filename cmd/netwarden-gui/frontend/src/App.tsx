import { AppShell, type AppView } from "@/app/AppShell"
import { MonitoringOverview } from "@/features/monitoring/MonitoringOverview"
import { DevicesView } from "@/features/devices/DevicesView"
import { IntegrityView } from "@/features/integrity/IntegrityView"
import { SettingsView } from "@/features/settings/SettingsView"
import { DiagnosticsView } from "@/features/diagnostics/DiagnosticsView"
import { useStoredState } from "@/lib/preferences"
import { useUnsavedChanges } from "@/app/unsaved-changes"

export default function App() {
  const [view, setView] = useStoredState<AppView>("netwarden.view", "devices")
  const { dirty } = useUnsavedChanges()
  const changeView = (next: AppView) => {
    if (next === view || !dirty || window.confirm("Discard unsaved settings changes?")) setView(next)
  }

  return (
    <AppShell view={view} onViewChange={changeView}>
      <MonitoringOverview />
      {view === "devices" && <DevicesView />}
      {view === "integrity" && <IntegrityView />}
      {view === "diagnostics" && <DiagnosticsView />}
      {view === "settings" && <SettingsView />}
    </AppShell>
  )
}
