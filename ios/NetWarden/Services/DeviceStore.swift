import Foundation
import Observation

@Observable
@MainActor
final class DeviceStore {
    private(set) var devices: [Device] = []
    private(set) var sourceDescription: String
    private(set) var snapshotNetwork: SnapshotNetwork?
    var searchText: String = ""

    init() {
        sourceDescription = "Bundled sample"
        loadBundled()
    }

    var filteredDevices: [Device] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !query.isEmpty else { return devices }
        return devices.filter { device in
            let haystack = [device.displayName, device.name, device.vendor ?? "", device.typeLabel, device.mac, device.ipv4 ?? ""]
                .joined(separator: " ")
                .lowercased()
            return haystack.contains(query)
        }
    }

    var onlineCount: Int {
        devices.filter { $0.online }.count
    }

    func setNickname(_ nickname: String, for deviceID: String) {
        guard let index = devices.firstIndex(where: { $0.id == deviceID }) else { return }
        let trimmed = nickname.trimmingCharacters(in: .whitespacesAndNewlines)
        devices[index].nickname = trimmed.isEmpty ? nil : trimmed
    }

    func clearNickname(for deviceID: String) {
        guard let index = devices.firstIndex(where: { $0.id == deviceID }) else { return }
        devices[index].nickname = nil
    }

    func importSnapshot(from url: URL) throws {
        let data = try Data(contentsOf: url)
        let snapshot = try decode(data)
        guard !snapshot.devices.isEmpty else {
            throw DeviceStoreError.emptySnapshot
        }
        devices = snapshot.devices
        snapshotNetwork = snapshot.network
        sourceDescription = "Imported from \(url.lastPathComponent)"
    }

    func resetToSample() {
        sourceDescription = "Bundled sample"
        loadBundled()
    }

    private func loadBundled() {
        guard let url = Bundle.main.url(forResource: "sample-snapshot", withExtension: "json"),
              let data = try? Data(contentsOf: url) else {
            devices = []
            return
        }
        if let snapshot = try? decode(data) {
            devices = snapshot.devices
            snapshotNetwork = snapshot.network
        } else {
            devices = []
        }
    }

    private func decode(_ data: Data) throws -> ScanSnapshot {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode(ScanSnapshot.self, from: data)
    }
}

enum DeviceStoreError: LocalizedError {
    case emptySnapshot

    var errorDescription: String? {
        switch self {
        case .emptySnapshot:
            return "The snapshot does not contain any devices."
        }
    }
}