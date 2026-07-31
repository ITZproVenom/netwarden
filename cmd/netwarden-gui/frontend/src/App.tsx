import { AppShell, type AppView } from "@/app/AppShell"
import { DevicesView } from "@/features/devices/DevicesView"
import { IntegrityView } from "@/features/integrity/IntegrityView"
import { SettingsView } from "@/features/settings/SettingsView"
import { DiagnosticsView } from "@/features/diagnostics/DiagnosticsView"
import { useStoredState } from "@/lib/preferences"
import { useUnsavedChanges } from "@/app/unsaved-changes"
import { BandwidthMonitorView } from "@/features/bandwidth/BandwidthMonitorView"

export default function App() {
  const [view, setView] = useStoredState<AppView>("netwarden.view", "devices")
  const { dirty } = useUnsavedChanges()
  const changeView = (next: AppView) => {
    if (next === view || !dirty || window.confirm("Discard unsaved settings changes?")) setView(next)
  }

  return (
    <AppShell view={view} onViewChange={changeView}>
      {view === "devices" && <DevicesView />}
      {view === "bandwidth" && <BandwidthMonitorView />}
      {view === "integrity" && (
        <section className="py-7 sm:py-9">
          <IntegrityView />
        </section>
      )}
      {view === "diagnostics" && (
        <section className="py-7 sm:py-9">
          <DiagnosticsView />
        </section>
      )}
      {view === "settings" && (
        <section className="py-7 sm:py-9">
          <SettingsView />
        </section>
      )}
    </AppShell>
  )
}
