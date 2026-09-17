import Foundation
import Darwin

struct InterfaceAddress: Identifiable, Hashable {
    var id: String { "\(name)|\(family)|\(address ?? "nil")" }

    let name: String
    let family: String
    let address: String?
    let isLinkLocal: Bool
}

enum InterfaceProbe {
    static func addresses() -> [InterfaceAddress] {
        var pointer: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&pointer) == 0, let first = pointer else { return [] }
        defer { freeifaddrs(first) }

        var result: [InterfaceAddress] = []
        var current: UnsafeMutablePointer<ifaddrs>? = first
        while let cursor = current {
            let next = cursor.pointee.ifa_next

            if let sa = cursor.pointee.ifa_addr {
                let family = sa.pointee.sa_family
                let loopback = cursor.pointee.ifa_flags & UInt32(IFF_LOOPBACK)

                var familyName: String?
                switch family {
                case sa_family_t(AF_INET):
                    familyName = "IPv4"
                case sa_family_t(AF_INET6):
                    familyName = "IPv6"
                default:
                    familyName = nil
                }

                if let familyName, loopback == 0 {
                    var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    let status = getnameinfo(
                        sa,
                        socklen_t(sa.pointee.sa_len),
                        &host,
                        socklen_t(host.count),
                        nil,
                        0,
                        NI_NUMERICHOST
                    )
                    if status == 0 {
                        let address = String(cString: host)
                        let linkLocal = familyName == "IPv4"
                            ? address.hasPrefix("169.254.")
                            : address.lowercased().hasPrefix("fe80:")
                        result.append(InterfaceAddress(
                            name: String(cString: cursor.pointee.ifa_name),
                            family: familyName,
                            address: address,
                            isLinkLocal: linkLocal
                        ))
                    }
                }
            }

            current = next
        }

        return result.sorted { $0.name == $1.name ? $0.family < $1.family : $0.name < $1.name }
    }
}