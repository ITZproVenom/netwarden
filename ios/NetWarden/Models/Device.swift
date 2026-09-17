import Foundation

struct ScanSnapshot: Codable {
    var version: Int
    var network: SnapshotNetwork?
    var devices: [Device]
}

struct SnapshotNetwork: Codable {
    var ssid: String?
    var localIPv4: String?
    var gatewayIPv4: String?
    var prefix: String?
}

struct Device: Identifiable, Codable, Hashable {
    var id: String { mac }

    let mac: String
    var name: String
    var vendor: String?
    var type: String?
    var nickname: String?
    var online: Bool
    var ipv4: String?
    var linkLocalIPv6: String?
    var globalIPv6: String?
    var firstSeen: Date?
    var lastSeen: Date?
    var isSelf: Bool
}

extension Device {
    var displayName: String {
        if let nickname, !nickname.isEmpty {
            return nickname
        }
        return name
    }

    var typeLabel: String {
        type ?? "Unknown"
    }

    var addressSummary: String {
        var parts: [String] = []
        if let ipv4, !ipv4.isEmpty { parts.append(ipv4) }
        if let globalIPv6, !globalIPv6.isEmpty { parts.append(globalIPv6) }
        if let linkLocalIPv6, !linkLocalIPv6.isEmpty { parts.append(linkLocalIPv6) }
        return parts.isEmpty ? "No known addresses" : parts.joined(separator: "  ")
    }
}