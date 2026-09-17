import Foundation

enum Formatters {
    /// Byte counts, e.g. "4.2 MB".
    static func bytes(_ count: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(count), countStyle: .file)
    }

    /// Bytes per second, e.g. "1.2 MB/s".
    static func bytesPerSecond(_ bps: UInt64) -> String {
        "\(bytes(bps))/s"
    }

    /// A rate in either MB/s or Mbps units.
    static func rate(_ bps: UInt64, asBits: Bool) -> String {
        if asBits {
            let mbps = Double(bps) / 1_000_000.0
            if mbps >= 1 {
                return String(format: "%.2f Mbps", mbps)
            }
            return String(format: "%.0f Kbps", Double(bps) / 1_000.0)
        }
        return bytesPerSecond(bps)
    }

    static func shortTime(_ date: Date?) -> String {
        guard let date else { return "—" }
        return date.formatted(date: .omitted, time: .shortened)
    }

    static func shortDateTime(_ date: Date?) -> String {
        guard let date else { return "—" }
        return date.formatted(date: .abbreviated, time: .shortened)
    }
}