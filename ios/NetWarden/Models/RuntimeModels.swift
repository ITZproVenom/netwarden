import Foundation

/// Mirrors the desktop app's severity/value vocabulary.
enum Severity: String, Codable {
    case info
    case warning
    case error
}

/// A unified runtime/discovery/integrity/control/bandwidth event.
struct ActivityEvent: Identifiable, Hashable {
    let id = UUID()
    let at: Date
    let kind: String
    let severity: Severity
    let title: String
    let detail: String
}

/// A device claiming the gateway address with an unexpected MAC.
struct GatewayConflict: Identifiable, Hashable {
    let id = UUID()
    let gatewayIP: String
    let expectedMAC: String
    let claimedMAC: String
    let firstSeen: Date
    var lastSeen: Date
    var count: Int
    var active: Bool
}

struct IPv6PrefixModel: Hashable {
    let prefix: String
    let onLink: Bool
    let autonomous: Bool
    let validUntil: Date?
    let preferredUntil: Date?
}

struct RouterIdentity: Hashable {
    let routerIP: String
    let mac: String
}

struct IPv6RouterModel: Identifiable, Hashable {
    var id: String { ip }
    let ip: String
    let mac: String?
    let preference: Int8
    let expiresAt: Date?
    let prefixes: [IPv6PrefixModel]

    var preferenceLabel: String {
        switch preference {
        case 3: return "High"
        case 1: return "Medium"
        default: return "Low"
        }
    }
}

struct IPv6RouterConflict: Identifiable, Hashable {
    var id: String { "\(routerIP)-\(claimedMAC)" }
    let routerIP: String
    let expectedMAC: String
    let claimedMAC: String
    let firstSeen: Date
    var lastSeen: Date
    var count: Int
    var active: Bool
}

struct IPv6NetworkModel: Hashable {
    let defaultRouterIP: String?
    let defaultRouterMAC: String?
    let routers: [IPv6RouterModel]
    let conflicts: [IPv6RouterConflict]
    let trustedIdentities: [RouterIdentity]
}

struct BandwidthPoint: Identifiable, Hashable {
    var id: Date { at }
    let at: Date
    let uploadBPS: Int
    let downloadBPS: Int
}

struct BandwidthMeasurementModel: Identifiable, Hashable {
    var id: String { mac }
    let mac: String
    let deviceName: String
    let uploadBPS: Int
    let downloadBPS: Int
    let uploadBytes: UInt64
    let downloadBytes: UInt64
    let peakUploadBPS: Int
    let peakDownloadBPS: Int
    let history: [BandwidthPoint]

    var combinedBPS: Int { uploadBPS + downloadBPS }
}

struct BandwidthBucket: Identifiable, Hashable {
    var id: String { "\(granularity)-\(start.timeIntervalSince1970)" }
    let granularity: String
    let start: Date
    let uploadBytes: UInt64
    let downloadBytes: UInt64
    let peakUploadBPS: Int
    let peakDownloadBPS: Int
}

struct BandwidthHealthModel {
    let activeWarning: Bool
    let recentQueueDrops: UInt64
    let recentSendErrors: UInt64
    let queueCapacity: Int
    let queueByteCapacity: Int64
    let uploadQueueBytes: Int64
    let downloadQueueBytes: Int64
    let sampledAt: Date

    var statusLabel: String {
        activeWarning ? "Attention" : "Healthy"
    }
}

struct ControlAuditEntry: Identifiable, Hashable {
    let id = UUID()
    let at: Date
    let operation: String
    let outcome: String
    let targets: [String]

    var operationTitle: String {
        operation.replacingOccurrences(of: "_", with: " ").capitalized
    }
}

struct LimitPolicy: Hashable {
    var downloadBitsPerSecond: UInt64
    var uploadBitsPerSecond: UInt64
    var burstBytes: Int

    var isLimited: Bool {
        downloadBitsPerSecond > 0 || uploadBitsPerSecond > 0
    }
}

enum BandwidthUnit: String, CaseIterable, Identifiable {
    case bytes = "MB/s"
    case bits = "Mbps"

    var id: String { rawValue }
}

struct HistorySummaryModel {
    let devices: Int
    let conflicts: Int
    let oldest: Date?
    let newest: Date?
}