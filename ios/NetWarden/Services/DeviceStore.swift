import Foundation
import Observation

@Observable
@MainActor
final class DeviceStore {
    private(set) var devices: [Device] = []
    private(set) var sourceDescription: String
    private(set) var snapshotNetwork: SnapshotNetwork?
    private(set) var selfMAC: String?
    private(set) var lastScan: LocalNetworkScan?
    var searchText: String = ""

    /// True only while the registry holds the bundled synthetic sample, which is
    /// an opt-in demo. A live scan replaces it instead of merging with it.
    private var showingSample = false

    init() {
        sourceDescription = "Not scanned yet"
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

    func setNickname(_ nickname: String, for deviceID: String) {        guard let index = devices.firstIndex(where: { $0.id == deviceID }) else { return }
        let trimmed = nickname.trimmingCharacters(in: .whitespacesAndNewlines)
        devices[index].nickname = trimmed.isEmpty ? nil : trimmed
    }

    func clearNickname(for deviceID: String) {
        guard let index = devices.firstIndex(where: { $0.id == deviceID }) else { return }
        devices[index].nickname = nil
    }

    func setSSID(_ ssid: String?) {
        guard !devices.isEmpty || lastScan != nil else { return }
        snapshotNetwork = SnapshotNetwork(
            ssid: ssid,
            localIPv4: snapshotNetwork?.localIPv4,
            gatewayIPv4: snapshotNetwork?.gatewayIPv4,
            prefix: snapshotNetwork?.prefix
        )
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
        showingSample = false
    }

    func resetToSample() {
        sourceDescription = "Bundled sample (synthetic)"
        lastScan = nil
        selfMAC = nil
        loadBundled()
        showingSample = true
    }

    /// Merge a real on-device scan into the registry. Discovered hosts become
    /// known devices (preserving nicknames and history for existing MACs), and
    /// devices from the imported snapshot that were not seen are marked
    /// offline rather than dropped.
    func applyScan(_ scan: LocalNetworkScan) {
        lastScan = scan
        selfMAC = scan.selfMAC

        var existing = [String: Device]()
        for device in devices {
            existing[device.mac] = device
        }

        snapshotNetwork = SnapshotNetwork(
            ssid: snapshotNetwork?.ssid,
            localIPv4: scan.primaryIPv4 ?? snapshotNetwork?.localIPv4,
            gatewayIPv4: scan.gatewayIPv4 ?? snapshotNetwork?.gatewayIPv4,
            prefix: scan.netmask ?? snapshotNetwork?.prefix
        )

        var updated: [Device] = []
        var seen = Set<String>()

        if let selfMAC = scan.selfMAC, let ip = scan.primaryIPv4 {
            var selfDevice = existing[selfMAC] ?? Device(
                mac: selfMAC,
                name: "This iPhone",
                vendor: "Apple",
                type: nil,
                nickname: nil,
                online: true,
                ipv4: ip,
                linkLocalIPv6: nil,
                globalIPv6: nil,
                firstSeen: .now,
                lastSeen: .now,
                isSelf: true,
                role: "This device",
                controlState: nil,
                addresses: nil
            )
            selfDevice.ipv4 = ip
            selfDevice.isSelf = true
            selfDevice.online = true
            selfDevice.role = "This device"
            selfDevice.lastSeen = .now
            updated.append(selfDevice)
            seen.insert(selfMAC)
        }

        for host in scan.hosts {
            let mac = host.mac ?? "ip-\(host.ip)"
            guard !seen.contains(mac) else { continue }
            seen.insert(mac)
            if var device = existing[mac] {
                device.ipv4 = host.ip
                device.online = true
                device.lastSeen = .now
                if device.vendor == nil { device.vendor = host.vendor }
                if host.isGateway { device.role = "Gateway" }
                if let name = host.name, !name.isEmpty, Self.isGenericName(device.name) {
                    device.name = name
                }
                if device.type == nil, let model = host.model, !model.isEmpty {
                    device.type = model
                }
                updated.append(device)
            } else {
                updated.append(Device(
                    mac: mac,
                    name: Self.displayName(for: host),
                    vendor: host.vendor,
                    type: host.model,
                    nickname: nil,
                    online: true,
                    ipv4: host.ip,
                    linkLocalIPv6: nil,
                    globalIPv6: nil,
                    firstSeen: .now,
                    lastSeen: .now,
                    isSelf: false,
                    role: host.isGateway ? "Gateway" : nil,
                    controlState: nil,
                    addresses: [host.ip]
                ))
            }
        }

        for device in devices where !seen.contains(device.mac) {
            guard !showingSample else { continue }
            var offline = device
            offline.online = false
            updated.append(offline)
        }

        showingSample = false
        devices = updated
        sourceDescription = scan.hosts.isEmpty
            ? "Live scan · no hosts responded"
            : "Live scan · \(scan.hosts.count) host\(scan.hosts.count == 1 ? "" : "s")"
    }

    /// Merge real hostnames learned asynchronously from reverse DNS for devices
    /// that Bonjour did not name.
    func applyResolvedNames(_ names: [String: String]) {
        guard !names.isEmpty else { return }
        var updated = devices
        for index in updated.indices {
            guard updated[index].nickname == nil else { continue }
            guard let ip = updated[index].ipv4, let name = names[ip], !name.isEmpty else { continue }
            if Self.isGenericName(updated[index].name) {
                updated[index].name = name
            }
        }
        devices = updated
    }

    private static func displayName(for host: DiscoveredHost) -> String {
        if let name = host.name, !name.isEmpty { return name }
        if let model = host.model, !model.isEmpty {
            return host.vendor.map { "\($0) \(model)" } ?? model
        }
        if let vendor = host.vendor { return "\(vendor) device" }
        return host.isGateway ? "Gateway" : "Unknown device"
    }

    private static func isGenericName(_ name: String) -> Bool {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        return trimmed.isEmpty
            || trimmed == "Device"
            || trimmed == "Gateway"
            || trimmed == "Unknown device"
            || trimmed.hasSuffix(" device")
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