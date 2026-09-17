import SwiftUI

struct NetworkView: View {
    @Environment(StandaloneRuntime.self) private var runtime
    @State private var interfaces: [InterfaceAddress] = []
    @State private var wifi: WiFiDetails?
    @State private var wifiChecked = false
    @State private var scanner = MDNSScanner()
    @State private var showAbout = false

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
                    overviewCard
                    runtimeCard
                    identityCard
                    nearbyServicesCard
                    if !ipv4.isEmpty {
                        addressesCard(systemImage: "globe", title: "IPv4 Addresses", items: ipv4)
                    }
                    if !ipv6.isEmpty {
                        addressesCard(systemImage: "globe.americas", title: "IPv6 Addresses", items: ipv6)
                    }
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
            }
            .background(AppBackground())
            .navigationTitle("Network")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showAbout = true
                    } label: {
                        Image(systemName: "scope")
                    }
                    .accessibilityLabel("Feature scope")
                }
            }
            .sheet(isPresented: $showAbout) {
                AboutView()
            }
            .task { await refresh() }
            .refreshable { await refresh() }
        }
    }

    private var overviewCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            PanelHeader(systemImage: "rectangle.3.group", title: "Network overview", subtitle: "Know what's on your network.")
            LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible())], spacing: 12) {
                statTile(title: "Known devices", value: "\(runtime.knownDeviceCount)", icon: "network")
                statTile(title: "Online now", value: "\(runtime.onlineCount)", icon: "circle.fill")
                statTile(title: "Current scan", value: runtime.scanning ? "Running" : "Idle", icon: runtime.scanning ? "rays" : "dot.radiowaves.left.and.right")
                statTile(title: "Gateway alerts", value: "\(runtime.totalConflictCount)", icon: "shield")
                statTile(title: "Monitored", value: "\(runtime.monitoredCount)", icon: "eye")
                statTile(title: "Limited", value: "\(runtime.limitedCount)", icon: "speedometer")
            }
        }
        .padding(18)
        .glassPanel()
    }

    private func statTile(title: String, value: String, icon: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: icon)
                    .font(.caption)
                    .foregroundStyle(.tint)
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text(value)
                .font(.title3.weight(.semibold))
                .lineLimit(1)
                .minimumScaleFactor(0.6)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassPanel(cornerRadius: 16)
    }

    private var runtimeCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            PanelHeader(
                systemImage: "play.rectangle",
                title: "Scanning & monitoring",
                subtitle: runtime.running ? "Monitoring active · demonstration mode" : "Monitoring inactive",
                tag: "Experimental"
            )
            if let lastScanAt = runtime.lastScanAt {
                InfoRow(label: "Last scan", value: Formatters.shortDateTime(lastScanAt))
            }
            if runtime.running {
                Button {
                    runtime.toggleRuntime()
                } label: {
                    Label("Stop monitoring", systemImage: "stop.fill")
                }
                .glassButton()
            } else {
                Button {
                    runtime.toggleRuntime()
                } label: {
                    Label("Start monitoring", systemImage: "play.fill")
                }
                .glassButton(prominent: true)
            }
            HStack(spacing: 12) {
                Button {
                    runtime.startScan()
                } label: {
                    if runtime.scanning {
                        ProgressView()
                            .padding(.horizontal, 4)
                    } else {
                        Label("Scan now", systemImage: "dot.radiowaves.left.and.right")
                    }
                }
                .glassButton()
                .disabled(runtime.scanning)
                Spacer()
                Toggle("Periodic discovery", isOn: Binding(
                    get: { runtime.periodicScanEnabled },
                    set: { _ in runtime.togglePeriodicScan() }
                ))
                .font(.footnote)
            }
            Text("Live ARP/NDP probing requires raw packets and cannot run on iPhone. Scan state and monitoring are simulated from the imported snapshot for a faithful standalone build; enforcing controls needs the desktop host.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(18)
        .glassPanel()
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

    private var nearbyServicesCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(
                systemImage: "antenna.radiowaves.left.and.right",
                title: "Nearby services",
                subtitle: scanner.isScanning ? scanner.statusMessage : "mDNS / Bonjour browsing is stopped"
            )
            if scanner.isScanning {
                if scanner.services.isEmpty {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text("Searching for services advertised over mDNS/Bonjour…")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                } else {
                    ForEach(Array(scanner.sortedGroups.prefix(4))) { group in
                        Text(group.type)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                        ForEach(group.services.prefix(3)) { service in
                            DiscoverRow(service: service)
                        }
                        if group.id != scanner.sortedGroups.prefix(4).last?.id {
                            Divider()
                            .padding(.vertical, 4)
                        }
                    }
                }
            } else {
                Text("Only services that advertise themselves are visible; iOS cannot enumerate every device.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Button(scanner.isScanning ? "Stop browsing" : "Browse services") {
                if scanner.isScanning {
                    scanner.stop()
                } else {
                    scanner.start()
                }
            }
            .glassButton()
            .font(.footnote)
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