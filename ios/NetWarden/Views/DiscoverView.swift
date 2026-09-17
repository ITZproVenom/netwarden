import SwiftUI

struct DiscoverView: View {
    @State private var scanner = MDNSScanner()

    var body: some View {
        NavigationStack {
            Group {
                if scanner.isScanning {
                    content
                } else {
                    stoppedState
                }
            }
            .background(AppBackground())
            .navigationTitle("Discover")
            .toolbar {
                if scanner.isScanning {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Stop") {
                            scanner.stop()
                        }
                    }
                }
            }
            .onAppear { scanner.start() }
            .onDisappear { scanner.stop() }
        }
    }

    private var content: some View {
        List {
            Section {
                if scanner.services.isEmpty {
                    HStack(spacing: 10) {
                        ProgressView()
                        Text("Searching for services advertised over mDNS/Bonjour…")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 6)
                }
            }
            ForEach(scanner.sortedGroups) { group in
                Section(group.type) {
                    ForEach(group.services) { service in
                        DiscoverRow(service: service)
                    }
                }
            }
        }
        .scrollContentBackground(.hidden)
        .safeAreaInset(edge: .bottom) {
            if scanner.isScanning {
                HStack(spacing: 8) {
                    Image(systemName: "antenna.radiowaves.left.and.right")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(scanner.statusMessage)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .padding(14)
                .glassPanel(cornerRadius: 18)
                .padding(.horizontal)
                .padding(.bottom, 6)
            }
        }
    }

    private var stoppedState: some View {
        ContentUnavailableView {
            Label("Browsing stopped", systemImage: "antenna.radiowaves.left.and.right.slash")
        } description: {
            Text("NetWarden shows services this iPhone can reach over mDNS. It cannot enumerate every device; only services that advertise themselves are visible.")
        } actions: {
            Button("Start scan") {
                scanner.start()
            }
            .glassButton(prominent: true)
        }
    }
}

struct DiscoverRow: View {
    let service: DiscoveredService

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(service.name)
                .font(.body)
                .lineLimit(1)
            HStack(spacing: 8) {
                if !service.domain.isEmpty {
                    Text(service.domain)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if !service.interfaceNames.isEmpty {
                    Text(service.interfaceNames.joined(separator: ", "))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}