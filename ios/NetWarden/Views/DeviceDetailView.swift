import SwiftUI

struct DeviceDetailView: View {
    @Environment(DeviceStore.self) private var store
    @Environment(StandaloneRuntime.self) private var runtime
    @State private var nicknameText: String
    @State private var downloadLimitText: String
    @State private var uploadLimitText: String

    let device: Device

    init(device: Device) {
        self.device = device
        _nicknameText = State(initialValue: device.nickname ?? "")
        _downloadLimitText = State(initialValue: "0")
        _uploadLimitText = State(initialValue: "0")
    }

    private var policy: LimitPolicy? {
        runtime.limitPolicies[device.mac]
    }

    private var limitUnitFactor: Double {
        runtime.bandwidthUnit == .bits ? 1_000_000 : 8_000_000
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                identityCard
                addressesCard
                controlCard
                monitoringCard
                limitCard
                auditCard
                nicknameCard
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
        }
        .background(AppBackground())
        .navigationTitle(device.displayName)
        .navigationBarTitleDisplayMode(.inline)
    }

    private var identityCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(
                systemImage: device.online ? "circle.fill" : "circle",
                title: device.displayName,
                subtitle: "\(device.typeLabel) · \(device.roleLabel) · \(device.online ? "online now" : "offline")"
            )
            Divider()
            InfoRow(label: "MAC", value: device.mac)
            if let vendor = device.vendor {
                InfoRow(label: "Vendor", value: vendor)
            }
            InfoRow(label: "Control state", value: device.controlStateLabel)
            InfoRow(label: "First seen", value: Formatters.shortDateTime(device.firstSeen))
            InfoRow(label: "Last seen", value: Formatters.shortDateTime(device.lastSeen))
        }
        .padding(18)
        .glassPanel()
    }

    private var addressesCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(systemImage: "map", title: "Known addresses")
            InfoRow(label: "IPv4", value: device.ipv4 ?? "—")
            InfoRow(label: "IPv6", value: device.globalIPv6 ?? device.linkLocalIPv6 ?? "—")
            InfoRow(label: "Link-local", value: device.linkLocalIPv6 ?? "—")
        }
        .padding(18)
        .glassPanel()
    }

    private var controlCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(
                systemImage: device.hasControl ? "hand.raised.fill" : "hand.raised",
                title: "Device control",
                subtitle: device.controlStateLabel,
                tag: "Experimental"
            )
            HStack {
                Text("Disconnect isolates \(device.displayName) via ARP/NDP redirection; continuous control refreshes it and restore rolls back to legitimate address resolution.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 12) {
                Button {
                    runtime.disconnect(device)
                } label: {
                    Label("Disconnect", systemImage: "hand.raised.fill")
                }
                .glassButton(prominent: true)
                Button {
                    runtime.restore(device)
                } label: {
                    Label("Restore", systemImage: "arrow.uturn.backward")
                }
                .glassButton()
            }
            Text("iOS cannot redirect traffic; disconnects are recorded as a demonstration audit entry and are not enforced.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(18)
        .glassPanel()
    }

    private var monitoringCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(
                systemImage: "eye",
                title: "Traffic monitoring",
                subtitle: runtime.monitoredMACS.contains(device.mac) ? "Monitoring \(device.displayName)" : "Not monitored",
                tag: "Experimental"
            )
            if let measurement = runtime.measurement(for: device.mac) {
                if runtime.running {
                    InfoRow(label: "Live download", value: Formatters.rate(UInt64(measurement.downloadBPS), asBits: runtime.bandwidthUnit == .bits))
                    InfoRow(label: "Live upload", value: Formatters.rate(UInt64(measurement.uploadBPS), asBits: runtime.bandwidthUnit == .bits))
                } else {
                    InfoRow(label: "Last known download", value: Formatters.rate(UInt64(measurement.downloadBPS), asBits: runtime.bandwidthUnit == .bits))
                    InfoRow(label: "Last known upload", value: Formatters.rate(UInt64(measurement.uploadBPS), asBits: runtime.bandwidthUnit == .bits))
                }
                InfoRow(label: "Total download", value: Formatters.bytes(measurement.downloadBytes))
                InfoRow(label: "Total upload", value: Formatters.bytes(measurement.uploadBytes))
                InfoRow(label: "Peak download", value: Formatters.rate(UInt64(measurement.peakDownloadBPS), asBits: runtime.bandwidthUnit == .bits))
                InfoRow(label: "Peak upload", value: Formatters.rate(UInt64(measurement.peakUploadBPS), asBits: runtime.bandwidthUnit == .bits))
            } else {
                Text("No traffic observed for this device.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Button {
                runtime.toggleMonitor(for: device)
            } label: {
                Text(runtime.monitoredMACS.contains(device.mac) ? "Stop monitoring" : "Start monitoring")
            }
            .glassButton()
        }
        .padding(18)
        .glassPanel()
    }

    private var limitCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(
                systemImage: "speedometer",
                title: "Bandwidth limit",
                subtitle: policy?.isLimited == true ? "Limited" : "Unlimited",
                tag: "Experimental"
            )
            Picker("Unit", selection: Bindable(runtime).bandwidthUnit) {
                ForEach(BandwidthUnit.allCases) { unit in
                    Text(unit.rawValue).tag(unit)
                }
            }
            .pickerStyle(.segmented)
            HStack(spacing: 10) {
                TextField("Download", text: $downloadLimitText)
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.decimalPad)
                    .monospacedDigit()
                Text(runtime.bandwidthUnit.rawValue)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 10) {
                TextField("Upload", text: $uploadLimitText)
                    .textFieldStyle(.roundedBorder)
                    .keyboardType(.decimalPad)
                    .monospacedDigit()
                Text(runtime.bandwidthUnit.rawValue)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            HStack(spacing: 12) {
                Button {
                    applyLimit()
                } label: {
                    Label(policy?.isLimited == true ? "Update limit" : "Apply limit", systemImage: "checkmark.circle")
                }
                .glassButton(prominent: true)
                Button {
                    runtime.setLimit(nil, for: device)
                    downloadLimitText = "0"
                    uploadLimitText = "0"
                } label: {
                    Label("Remove limit", systemImage: "xmark.circle")
                }
                .glassButton()
            }
            Text("A limit is recorded as the policy the desktop helper would enforce. Zero in both fields means unlimited.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(18)
        .glassPanel()
    }

    private var auditCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(
                systemImage: "clock.arrow.circlepath",
                title: "Recent control activity",
                tag: "Experimental"
            )
            let entries = runtime.auditEntries(for: device)
            if entries.isEmpty {
                Text("No control audit entries for this device.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(entries) { entry in
                    HStack(spacing: 10) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.operationTitle)
                                .font(.subheadline)
                            Text(entry.outcome.replacingOccurrences(of: "_", with: " "))
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(Formatters.shortTime(entry.at))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .padding(18)
        .glassPanel()
    }

    private var nicknameCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(systemImage: "textformat.alt", title: "Nickname", subtitle: "Stored on this iPhone only")
            HStack(spacing: 10) {
                TextField("Add a memorable name", text: $nicknameText)
                    .textFieldStyle(.roundedBorder)
                Button("Save") {
                    store.setNickname(nicknameText, for: device.id)
                }
                .glassButton(prominent: true)
            }
            Button("Clear nickname") {
                nicknameText = ""
                store.clearNickname(for: device.id)
            }
            .glassButton()
        }
        .padding(18)
        .glassPanel()
    }

    private func applyLimit() {
        let download = (Double(downloadLimitText) ?? 0) * limitUnitFactor
        let upload = (Double(uploadLimitText) ?? 0) * limitUnitFactor
        let policy = LimitPolicy(
            downloadBitsPerSecond: UInt64(download),
            uploadBitsPerSecond: UInt64(upload),
            burstBytes: 1_048_576
        )
        runtime.setLimit(policy, for: device)
    }
}