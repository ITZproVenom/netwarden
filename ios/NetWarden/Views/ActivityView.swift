import SwiftUI

struct ActivityView: View {
    @Environment(StandaloneRuntime.self) private var runtime
    @State private var severityFilter: Severity?

    private var filtered: [ActivityEvent] {
        guard let severityFilter else { return runtime.activity }
        return runtime.activity.filter { $0.severity == severityFilter }
    }

    var body: some View {
        NavigationStack {
            Group {
                if filtered.isEmpty {
                    ContentUnavailableView(
                        "No events",
                        systemImage: "tray",
                        description: Text("Runtime, scan, integrity, control, and bandwidth events appear here.")
                    )
                } else {
                    List {
                        runtimeSection
                        Section {
                            ForEach(filtered) { event in
                                ActivityRow(event: event)
                            }
                        } header: {
                            Text("Unified activity")
                        } footer: {
                            Text("\(filtered.count) event\(filtered.count == 1 ? "" : "s")\(severityFilter != nil ? " · filtered" : "")")
                        }
                    }
                }
            }
            .background(AppBackground())
            .scrollContentBackground(.hidden)
            .navigationTitle("Activity")
            .toolbar {
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Menu {
                        Picker("Severity", selection: $severityFilter) {
                            Text("All").tag(Severity?.none)
                            Text("Info").tag(Severity?.some(.info))
                            Text("Warning").tag(Severity?.some(.warning))
                            Text("Error").tag(Severity?.some(.error))
                        }
                    } label: {
                        Image(systemName: severityFilter == nil ? "line.3.horizontal.decrease" : "line.3.horizontal.decrease.circle.fill")
                    }
                    Button {
                        runtime.clearActivity()
                    } label: {
                        Image(systemName: "trash")
                    }
                }
            }
        }
    }

    private var runtimeSection: some View {
        Section {
            runtimeStat(label: "Runtime state", value: runtime.running ? "Healthy" : "Idle", icon: "cpu")
            runtimeStat(label: "Restarts", value: "\(runtime.restartCount)", icon: "arrow.clockwise")
            runtimeStat(label: "Dropped events", value: "\(runtime.droppedEvents)", icon: "tray.full")
            runtimeStat(label: "Known devices", value: "\(runtime.knownDeviceCount)", icon: "network")
        } header: {
            Text("Support summary")
        }
    }

    private func runtimeStat(label: String, value: String, icon: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.subheadline)
                .foregroundStyle(.tint)
                .frame(width: 24)
            Text(label)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.subheadline.weight(.semibold))
        }
    }
}

struct ActivityRow: View {
    let event: ActivityEvent

    private var color: Color {
        switch event.severity {
        case .info: return .secondary
        case .warning: return .orange
        case .error: return .red
        }
    }

    private var icon: String {
        switch event.severity {
        case .info: return "info.circle"
        case .warning: return "exclamationmark.triangle.fill"
        case .error: return "xmark.octagon.fill"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: icon)
                    .font(.footnote)
                    .foregroundStyle(color)
                Text(event.kind)
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                Spacer()
                Text(Formatters.shortTime(event.at))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text(event.title)
                .font(.subheadline.weight(.semibold))
            if !event.detail.isEmpty {
                Text(event.detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }
}