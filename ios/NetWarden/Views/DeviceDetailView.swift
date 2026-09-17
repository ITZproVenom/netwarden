import SwiftUI

struct DeviceDetailView: View {
    @Environment(DeviceStore.self) private var store
    @State private var nicknameText: String

    let device: Device

    init(device: Device) {
        self.device = device
        _nicknameText = State(initialValue: device.nickname ?? "")
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                identityCard
                addressesCard
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
                subtitle: "\(device.typeLabel) · \(device.online ? "online now" : "offline")"
            )
            Divider()
            InfoRow(label: "MAC", value: device.mac)
            if let vendor = device.vendor {
                InfoRow(label: "Vendor", value: vendor)
            }
            InfoRow(label: "First seen", value: shortDate(device.firstSeen))
            InfoRow(label: "Last seen", value: shortDate(device.lastSeen))
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

    private func shortDate(_ date: Date?) -> String {
        guard let date else { return "—" }
        return date.formatted(date: .abbreviated, time: .shortened)
    }
}