import SwiftUI

struct NetworkView: View {
    @State private var interfaces: [InterfaceAddress] = []
    @State private var wifi: WiFiDetails?
    @State private var wifiChecked = false

    private var ipv4: [InterfaceAddress] {
        interfaces.filter { $0.family == "IPv4" }
    }

    private var ipv6: [InterfaceAddress] {
        interfaces.filter { $0.family == "IPv6" }
    }

    private var primaryIPv4: String? {
        (interfaces.first { $0.name == "en0" } ?? interfaces.first { $0.family == "IPv4" })?.address
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    identityCard
                    if !ipv4.isEmpty {
                        addressesCard(systemImage: "globe", title: "IPv4 Addresses", items: ipv4)
                    }
                    if !ipv6.isEmpty {
                        addressesCard(systemImage: "globe.americas", title: "IPv6 Addresses", items: ipv6)
                    }
                    limitationsCard
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
            }
            .background(AppBackground())
            .navigationTitle("Current Network")
            .task { await refresh() }
            .refreshable { await refresh() }
        }
    }

    private var identityCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 14) {
                Image(systemName: "iphone.radiowaves.left.and.right")
                    .font(.title2)
                    .foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text("This iPhone")
                        .font(.headline)
                    Text("Your device on the current network")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if wifiChecked {
                    Image(systemName: wifi?.ssid != nil ? "wifi" : "wifi.slash")
                        .font(.title3)
                        .foregroundStyle(wifi?.ssid != nil ? Color.green : Color.secondary)
                }
            }
            if let ssid = wifi?.ssid {
                InfoRow(label: "Network", value: ssid)
            } else if wifiChecked {
                InfoRow(label: "Network", value: "Wi-Fi details unavailable on this device")
            }
            if let primaryIPv4 {
                InfoRow(label: "Local IP", value: primaryIPv4)
            }
            InfoRow(label: "Interfaces", value: "\(interfaces.filter { !$0.isLinkLocal }.count) active")
        }
        .padding(18)
        .glassPanel()
    }

    private func addressesCard(systemImage: String, title: String, items: [InterfaceAddress]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(systemImage: systemImage, title: title)
            ForEach(items) { item in
                HStack(spacing: 10) {
                    Image(systemName: item.isLinkLocal ? "link" : "circle.fill")
                        .font(.caption)
                        .foregroundStyle(item.isLinkLocal ? Color.secondary : Color.green)
                        .frame(width: 18)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(item.address ?? "—")
                            .font(.body.monospaced())
                        Text(item.name + (item.isLinkLocal ? " · link-local" : ""))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                }
            }
        }
        .padding(18)
        .glassPanel()
    }

    private var limitationsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("What NetWarden can and cannot do on iPhone", systemImage: "info.circle")
                .font(.headline)
            Text("iPhone apps have no access to raw network packets, so live ARP/NDP scanning, gateway-security monitoring, device controls, and bandwidth limits remain desktop features. On iOS, NetWarden reports this device's own network identity, browses locally advertised mDNS services, and imports scan snapshots from the desktop app.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(18)
        .glassPanel()
    }

    private func refresh() async {
        interfaces = InterfaceProbe.addresses()
        guard !wifiChecked else { return }
        wifiChecked = true
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            WiFiInfo.fetchCurrent { details in
                wifi = details
                continuation.resume()
            }
        }
    }
}