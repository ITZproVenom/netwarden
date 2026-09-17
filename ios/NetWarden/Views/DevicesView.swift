import SwiftUI
import UniformTypeIdentifiers

struct DevicesView: View {
    @Environment(DeviceStore.self) private var store
    @State private var showImporter = false
    @State private var importError: Error?

    var body: some View {
        NavigationStack {
            Group {
                if store.devices.isEmpty {
                    ContentUnavailableView(
                        "No devices",
                        systemImage: "network",
                        description: Text("Load a scan snapshot exported from the NetWarden desktop app.")
                    )
                } else if store.filteredDevices.isEmpty {
                    ContentUnavailableView.search(text: store.searchText)
                } else {
                    List {
                        Section {
                            ForEach(store.filteredDevices) { device in
                                NavigationLink(value: device) {
                                    DeviceRow(device: device)
                                }
                            }
                        } footer: {
                            Text("\(store.filteredDevices.count) shown · \(store.onlineCount) online · Source: \(store.sourceDescription)")
                        }
                    }
                }
            }
            .background(AppBackground())
            .scrollContentBackground(.hidden)
            .navigationDestination(for: Device.self) { device in
                DeviceDetailView(device: device)
            }
            .navigationTitle("Devices")
            .searchable(text: Bindable(store).searchText, prompt: "Name, MAC, vendor…")
            .toolbar {
                ToolbarItemGroup(placement: .topBarTrailing) {
                    Menu {
                        Button {
                            showImporter = true
                        } label: {
                            Label("Import snapshot…", systemImage: "square.and.arrow.down")
                        }
                        Button {
                            store.resetToSample()
                        } label: {
                            Label("Restore sample", systemImage: "arrow.uturn.backward")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
            .fileImporter(
                isPresented: $showImporter,
                allowedContentTypes: [.json],
                allowsMultipleSelection: false
            ) { result in
                switch result {
                case .success(let urls):
                    guard let url = urls.first else { return }
                    do {
                        try store.importSnapshot(from: url)
                    } catch {
                        importError = error
                    }
                case .failure(let error):
                    importError = error
                }
            }
            .alert("Import failed", isPresented: Binding(get: { importError != nil }, set: { if !$0 { importError = nil } })) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(importError?.localizedDescription ?? "Unknown error")
            }
        }
    }
}

struct DeviceRow: View {
    let device: Device

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(device.online ? Color.green.opacity(0.18) : Color.secondary.opacity(0.12))
                Image(systemName: device.online ? "circle.fill" : "circle")
                    .font(.caption)
                    .foregroundStyle(device.online ? Color.green : Color.secondary)
            }
            .frame(width: 32, height: 32)

            VStack(alignment: .leading, spacing: 2) {
                Text(device.displayName)
                    .font(.body)
                    .lineLimit(1)
                HStack(spacing: 8) {
                    if let ipv4 = device.ipv4 {
                        Text(ipv4)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Text(device.typeLabel)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if device.isSelf {
                Text("This iPhone")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }
}