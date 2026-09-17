import Foundation
import Darwin

// The iOS SDK does not re-export `<net/route.h>` through the Darwin module, so
// the routing-message header and its flags are declared here. The layout is
// the public BSD ABI: `struct RouteMessageHeader` up to and including `rtm_inits`.
private struct RouteMessageHeader {
    var rtm_msglen: UInt16
    var rtm_version: UInt8
    var rtm_type: UInt8
    var rtm_hdrlen: UInt16
    var rtm_index: UInt16
    var rtm_flags: Int32
    var rtm_addrs: Int32
    var rtm_pid: Int32
    var rtm_seq: Int32
    var rtm_errno: Int32
    var rtm_use: Int32
    var rtm_inits: UInt32
}

private enum RouteFlag {
    static let gateway: Int32 = 0x2
    static let llinfo: Int32 = 0x400
}

private enum RouteAddressFlag {
    static let destination: Int32 = 0x1
    static let gateway: Int32 = 0x2
    static let netmask: Int32 = 0x4
    static let genmask: Int32 = 0x8
    static let interface: Int32 = 0x10
    static let interfaceAddress: Int32 = 0x20
    static let author: Int32 = 0x40
    static let broadcast: Int32 = 0x80

    static let ordered: [Int32] = [destination, gateway, netmask, genmask, interface, interfaceAddress, author, broadcast]
}

private let routeMessageIfInfo2: Int32 = 0x12

/// Real on-device local-network inspection using public BSD interfaces.
///
/// This is the closest an iOS app can get to the desktop discovery stack:
///
/// - `getifaddrs` for interface addresses, netmasks, and self identity.
/// - `sysctl(NET_RT_IFLIST2)` for real interface byte counters (throughput).
/// - `sysctl(NET_RT_DUMP)` for the operating system's default routes.
/// - `sysctl(NET_RT_FLAGS / RTF_LLINFO)` for the kernel ARP cache; this is how
///   we learn real on-link neighbors and their MAC addresses.
/// - A unicast UDP sweep to each host in the local subnet so the kernel
///   performs neighbor resolution for hosts we have not talked to yet.
///
/// Raw capture, packet injection, and ARP/NDP redirection are not possible in
/// the iOS sandbox, so those remain labeled as non-enforceable elsewhere.

struct LocalInterfaceInfo: Hashable, Identifiable {
    var id: String { name }
    var name: String
    var ipv4: String?
    var netmask: String?
    var ipv6Global: [String]
    var ipv6LinkLocal: [String]
    var receivedBytes: UInt64
    var sentBytes: UInt64
}

struct ARPEntry: Hashable {
    var ip: String
    var mac: String
}

struct DiscoveredHost: Hashable, Identifiable {
    var id: String { ip }
    var ip: String
    var mac: String?
    var vendor: String?
    var isGateway: Bool
    var openPorts: [Int]
}

struct LocalNetworkScan {
    var interfaces: [LocalInterfaceInfo]
    var primaryInterface: String?
    var primaryIPv4: String?
    var netmask: String?
    var selfMAC: String?
    var gatewayIPv4: String?
    var gatewayMAC: String?
    var gatewayIPv6: String?
    var ipv6Prefixes: [String]
    var arpEntries: [ARPEntry]
    var hosts: [DiscoveredHost]
    var scannedAt: Date

    static let empty = LocalNetworkScan(
        interfaces: [],
        primaryInterface: nil,
        primaryIPv4: nil,
        netmask: nil,
        selfMAC: nil,
        gatewayIPv4: nil,
        gatewayMAC: nil,
        gatewayIPv6: nil,
        ipv6Prefixes: [],
        arpEntries: [],
        hosts: [],
        scannedAt: .distantPast
    )
}

enum LocalNetworkScanner {
    // MARK: - Entry point

    static func scan(progress: (String) -> Void = { _ in }) -> LocalNetworkScan {
        progress("Reading interfaces")
        let interfaces = interfaceInfo()
        let primary = interfaces.first { $0.name == "en0" && $0.ipv4 != nil }
            ?? interfaces.first { $0.ipv4 != nil && !$0.isTunnel }
        let selfMAC = hardwareAddress(for: primary?.name)

        let ipv6Prefixes = prefixes(from: interfaces)
        let routes = defaultRoutes()

        progress("Probing local subnet")
        var arp = arpCache()
        if let ipv4 = primary?.ipv4, let mask = primary?.netmask {
            let hosts = hostAddresses(ip: ipv4, netmask: mask)
            probe(hosts: hosts)
            Thread.sleep(forTimeInterval: 0.9)
            arp = arpCache()
            if arp.isEmpty {
                // The kernel ARP table may be unavailable; fall back to a
                // bounded TCP reachability sweep so discovery still works.
                progress("ARP table unavailable, probing reachability")
                let reachable = reachabilitySweep(hosts: hosts)
                return assemble(
                    interfaces: interfaces,
                    primary: primary,
                    selfMAC: selfMAC,
                    routes: routes,
                    ipv6Prefixes: ipv6Prefixes,
                    arp: [],
                    reachable: reachable,
                    scannedAt: .now
                )
            }
        } else {
            progress("No routable IPv4 interface")
        }

        progress("Reading neighbor cache")
        return assemble(
            interfaces: interfaces,
            primary: primary,
            selfMAC: selfMAC,
            routes: routes,
            ipv6Prefixes: ipv6Prefixes,
            arp: arp,
            reachable: [],
            scannedAt: .now
        )
    }

    private static func assemble(
        interfaces: [LocalInterfaceInfo],
        primary: LocalInterfaceInfo?,
        selfMAC: String?,
        routes: (ipv4: String?, ipv6: String?),
        ipv6Prefixes: [String],
        arp: [ARPEntry],
        reachable: [String],
        scannedAt: Date
    ) -> LocalNetworkScan {
        let gatewayIPv4 = routes.ipv4 ?? primary?.ipv4.map { derivedGateway(from: $0) }
        var hosts: [DiscoveredHost] = []
        var seen = Set<String>()

        for entry in arp where isUnicast(entry.ip) {
            guard entry.ip != primary?.ipv4 else { continue }
            seen.insert(entry.ip)
            hosts.append(DiscoveredHost(
                ip: entry.ip,
                mac: entry.mac,
                vendor: OUIVendor.lookup(entry.mac),
                isGateway: entry.ip == gatewayIPv4,
                openPorts: []
            ))
        }

        for ip in reachable where !seen.contains(ip) && ip != primary?.ipv4 {
            seen.insert(ip)
            hosts.append(DiscoveredHost(ip: ip, mac: nil, vendor: nil, isGateway: ip == gatewayIPv4, openPorts: []))
        }

        let gatewayMAC = gatewayIPv4.flatMap { gateway in arp.first { $0.ip == gateway }?.mac }

        return LocalNetworkScan(
            interfaces: interfaces,
            primaryInterface: primary?.name,
            primaryIPv4: primary?.ipv4,
            netmask: primary?.netmask,
            selfMAC: selfMAC,
            gatewayIPv4: gatewayIPv4,
            gatewayMAC: gatewayMAC,
            gatewayIPv6: routes.ipv6,
            ipv6Prefixes: ipv6Prefixes,
            arpEntries: arp,
            hosts: hosts.sorted { (ipv4Value($0.ip) ?? 0) < (ipv4Value($1.ip) ?? 0) },
            scannedAt: scannedAt
        )
    }

    // MARK: - Throughput

    /// Real aggregate interface byte counters, used to derive live throughput.
    static func interfaceCounters() -> (received: UInt64, sent: UInt64) {
        let info = interfaceInfo()
        let active = info.filter { !$0.isTunnel && !$0.name.hasPrefix("llw") && !$0.name.hasPrefix("awdl") }
        let received = active.reduce(UInt64(0)) { $0 + $1.receivedBytes }
        let sent = active.reduce(UInt64(0)) { $0 + $1.sentBytes }
        return (received, sent)
    }

    // MARK: - Interfaces

    private static func interfaceInfo() -> [LocalInterfaceInfo] {
        let addresses = interfaceAddresses()

        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0]
        var length = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &length, nil, 0) == 0, length > 0 else {
            return addresses.keys.sorted().map { name in
                let set = addresses[name] ?? InterfaceAddressSet()
                return LocalInterfaceInfo(
                    name: name,
                    ipv4: set.ipv4,
                    netmask: set.netmask,
                    ipv6Global: set.globalIPv6,
                    ipv6LinkLocal: set.linkLocalIPv6,
                    receivedBytes: 0,
                    sentBytes: 0
                )
            }
        }

        var buffer = [UInt8](repeating: 0, count: length)
        guard sysctl(&mib, UInt32(mib.count), &buffer, &length, nil, 0) == 0 else {
            return []
        }

        var result: [LocalInterfaceInfo] = []
        var offset = 0
        buffer.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            while offset + MemoryLayout<if_msghdr>.size <= length {
                let header = base.loadUnaligned(fromByteOffset: offset, as: if_msghdr.self)
                let messageLength = Int(header.ifm_msglen)
                guard messageLength > 0 else { break }

                if Int32(header.ifm_type) == routeMessageIfInfo2 {
                    let message = base.loadUnaligned(fromByteOffset: offset, as: if_msghdr2.self)
                    if message.ifm_flags & Int32(IFF_LOOPBACK) == 0 {
                        var nameBuffer = [CChar](repeating: 0, count: Int(IFNAMSIZ) + 1)
                        if if_indextoname(UInt32(message.ifm_index), &nameBuffer) != nil {
                            let name = String(cString: nameBuffer)
                            let set = addresses[name] ?? InterfaceAddressSet()
                            result.append(LocalInterfaceInfo(
                                name: name,
                                ipv4: set.ipv4,
                                netmask: set.netmask,
                                ipv6Global: set.globalIPv6,
                                ipv6LinkLocal: set.linkLocalIPv6,
                                receivedBytes: message.ifm_data.ifi_ibytes,
                                sentBytes: message.ifm_data.ifi_obytes
                            ))
                        }
                    }
                }
                offset += messageLength
            }
        }

        return result.sorted { $0.name < $1.name }
    }

    private struct InterfaceAddressSet {
        var ipv4: String?
        var netmask: String?
        var globalIPv6: [String] = []
        var linkLocalIPv6: [String] = []
    }

    private static func interfaceAddresses() -> [String: InterfaceAddressSet] {
        var pointer: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&pointer) == 0, let first = pointer else { return [:] }
        defer { freeifaddrs(first) }

        var result: [String: InterfaceAddressSet] = [:]
        var current: UnsafeMutablePointer<ifaddrs>? = first
        while let cursor = current {
            let next = cursor.pointee.ifa_next
            let name = String(cString: cursor.pointee.ifa_name)

            if let addressPointer = cursor.pointee.ifa_addr,
               cursor.pointee.ifa_flags & UInt32(IFF_LOOPBACK) == 0 {
                let family = addressPointer.pointee.sa_family
                var set = result[name] ?? InterfaceAddressSet()
                if family == sa_family_t(AF_INET) {
                    set.ipv4 = numericHost(addressPointer)
                    if let maskPointer = cursor.pointee.ifa_netmask {
                        set.netmask = numericHost(maskPointer)
                    }
                } else if family == sa_family_t(AF_INET6), let host = numericHost(addressPointer) {
                    let lowered = host.lowercased()
                    if lowered.hasPrefix("fe80") {
                        if !set.linkLocalIPv6.contains(host) { set.linkLocalIPv6.append(host) }
                    } else if lowered != "::1" {
                        if !set.globalIPv6.contains(host) { set.globalIPv6.append(host) }
                    }
                }
                result[name] = set
            }
            current = next
        }
        return result
    }

    private static func hardwareAddress(for interfaceName: String?) -> String? {
        guard let interfaceName else { return nil }
        var pointer: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&pointer) == 0, let first = pointer else { return nil }
        defer { freeifaddrs(first) }

        var current: UnsafeMutablePointer<ifaddrs>? = first
        while let cursor = current {
            let next = cursor.pointee.ifa_next
            let name = String(cString: cursor.pointee.ifa_name)
            if name == interfaceName,
               let addressPointer = cursor.pointee.ifa_addr,
               addressPointer.pointee.sa_family == sa_family_t(AF_LINK) {
                let link = addressPointer.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { $0.pointee }
                let addressLength = Int(link.sdl_alen)
                let nameLength = Int(link.sdl_nlen)
                if addressLength == 6 {
                    var bytes = [UInt8](repeating: 0, count: 6)
                    withUnsafePointer(to: link.sdl_data) { tuplePointer in
                        tuplePointer.withMemoryRebound(to: UInt8.self, capacity: 12) { dataPointer in
                            for index in 0..<6 {
                                bytes[index] = dataPointer[nameLength + index]
                            }
                        }
                    }
                    return bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
                }
            }
            current = next
        }
        return nil
    }

    private static func numericHost(_ address: UnsafeMutablePointer<sockaddr>) -> String? {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let status = getnameinfo(
            address,
            socklen_t(address.pointee.sa_len),
            &host,
            socklen_t(host.count),
            nil,
            0,
            NI_NUMERICHOST
        )
        guard status == 0 else { return nil }
        return String(cString: host)
    }

    // MARK: - Routes

    static func defaultRoutes() -> (ipv4: String?, ipv6: String?) {
        (defaultRoute(family: AF_INET), defaultRoute(family: AF_INET6))
    }

    private static func defaultRoute(family: Int32) -> String? {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, family, NET_RT_DUMP, 0]
        var length = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &length, nil, 0) == 0, length > 0 else { return nil }
        var buffer = [UInt8](repeating: 0, count: length)
        guard sysctl(&mib, UInt32(mib.count), &buffer, &length, nil, 0) == 0 else { return nil }

        var gateway: String?
        var offset = 0
        buffer.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            while offset + MemoryLayout<RouteMessageHeader>.size <= length, gateway == nil {
                let message = base.loadUnaligned(fromByteOffset: offset, as: RouteMessageHeader.self)
                let messageLength = Int(message.rtm_msglen)
                guard messageLength > 0 else { break }

                if message.rtm_flags & RouteFlag.gateway != 0,
                   message.rtm_addrs & RouteAddressFlag.destination != 0,
                   message.rtm_addrs & RouteAddressFlag.gateway != 0 {
                    let parsed = addresses(in: message, at: base, offset: offset)
                    if isDefault(parsed.destination, family: family), let destination = parsed.gateway {
                        gateway = destination
                    }
                }
                offset += messageLength
            }
        }
        return gateway
    }

    private static func addresses(in message: RouteMessageHeader, at base: UnsafeRawPointer, offset: Int) -> (destination: String?, gateway: String?) {
        let order = RouteAddressFlag.ordered
        var cursor = offset + Int(message.rtm_hdrlen)
        let limit = offset + Int(message.rtm_msglen)
        var destination: String?
        var gateway: String?

        for flag in order {
            guard message.rtm_addrs & flag != 0 else { continue }
            guard cursor + 1 < limit, let parsed = parseSockaddr(base.advanced(by: cursor)) else { break }
            if flag == RouteAddressFlag.destination { destination = parsed.address }
            if flag == RouteAddressFlag.gateway { gateway = parsed.address }
            cursor += roundUp(parsed.length)
        }
        return (destination, gateway)
    }

    private static func isDefault(_ address: String?, family: Int32) -> Bool {
        guard let address else { return false }
        if family == AF_INET { return address == "0.0.0.0" }
        return address == "::" || address == "0:0:0:0:0:0:0:0"
    }

    // MARK: - ARP cache

    static func arpCache() -> [ARPEntry] {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RouteFlag.llinfo]
        var length = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &length, nil, 0) == 0, length > 0 else { return [] }
        var buffer = [UInt8](repeating: 0, count: length)
        guard sysctl(&mib, UInt32(mib.count), &buffer, &length, nil, 0) == 0 else { return [] }

        var entries: [ARPEntry] = []
        var offset = 0
        buffer.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            while offset + MemoryLayout<RouteMessageHeader>.size <= length {
                let message = base.loadUnaligned(fromByteOffset: offset, as: RouteMessageHeader.self)
                let messageLength = Int(message.rtm_msglen)
                guard messageLength > 0 else { break }

                if message.rtm_flags & RouteFlag.llinfo != 0,
                   message.rtm_addrs & RouteAddressFlag.destination != 0,
                   message.rtm_addrs & RouteAddressFlag.gateway != 0 {
                    let parsed = linkLayer(in: message, at: base, offset: offset)
                    if let ip = parsed.destination, let mac = parsed.mac, mac != "00:00:00:00:00:00" {
                        entries.append(ARPEntry(ip: ip, mac: mac))
                    }
                }
                offset += messageLength
            }
        }
        return entries.sorted { (ipv4Value($0.ip) ?? 0) < (ipv4Value($1.ip) ?? 0) }
    }

    private static func linkLayer(in message: RouteMessageHeader, at base: UnsafeRawPointer, offset: Int) -> (destination: String?, mac: String?) {
        let order = RouteAddressFlag.ordered
        var cursor = offset + Int(message.rtm_hdrlen)
        let limit = offset + Int(message.rtm_msglen)
        var destination: String?
        var mac: String?

        for flag in order {
            guard message.rtm_addrs & flag != 0 else { continue }
            guard cursor + 1 < limit, let parsed = parseSockaddr(base.advanced(by: cursor)) else { break }
            if flag == RouteAddressFlag.destination { destination = parsed.address }
            if flag == RouteAddressFlag.gateway { mac = parsed.mac }
            cursor += roundUp(parsed.length)
        }
        return (destination, mac)
    }

    // MARK: - Sockaddr parsing

    private struct ParsedSockaddr {
        var address: String?
        var mac: String?
        var length: Int
    }

    private static func parseSockaddr(_ pointer: UnsafeRawPointer) -> ParsedSockaddr? {
        let length = Int(pointer.load(as: UInt8.self))
        guard length > 0 else { return nil }
        let family = Int32(pointer.load(fromByteOffset: 1, as: UInt8.self))

        switch family {
        case AF_INET:
            var storage = pointer.loadUnaligned(as: sockaddr_in.self)
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &storage.sin_addr, &buffer, socklen_t(INET_ADDRSTRLEN))
            return ParsedSockaddr(address: String(cString: buffer), mac: nil, length: length)
        case AF_INET6:
            var storage = pointer.loadUnaligned(as: sockaddr_in6.self)
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            inet_ntop(AF_INET6, &storage.sin6_addr, &buffer, socklen_t(INET6_ADDRSTRLEN))
            return ParsedSockaddr(address: String(cString: buffer), mac: nil, length: length)
        case AF_LINK:
            let storage = pointer.loadUnaligned(as: sockaddr_dl.self)
            let nameLength = Int(storage.sdl_nlen)
            let addressLength = Int(storage.sdl_alen)
            guard addressLength == 6 else {
                return ParsedSockaddr(address: nil, mac: nil, length: length)
            }
            let dataOffset = MemoryLayout<sockaddr_dl>.size - 12
            var bytes = [UInt8](repeating: 0, count: 6)
            for index in 0..<6 {
                bytes[index] = pointer.load(fromByteOffset: dataOffset + nameLength + index, as: UInt8.self)
            }
            let mac = bytes.map { String(format: "%02x", $0) }.joined(separator: ":")
            return ParsedSockaddr(address: nil, mac: mac, length: length)
        default:
            return ParsedSockaddr(address: nil, mac: nil, length: length)
        }
    }

    private static func roundUp(_ length: Int) -> Int {
        (length + 3) & ~3
    }

    // MARK: - Active sweep

    private static func probe(hosts: [String]) {
        let descriptor = socket(AF_INET, SOCK_DGRAM, 0)
        guard descriptor >= 0 else { return }
        defer { close(descriptor) }

        for host in hosts {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = UInt16(9).bigEndian
            guard inet_pton(AF_INET, host, &address.sin_addr) == 1 else { continue }
            withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                    _ = sendto(descriptor, "", 0, 0, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
    }

    private static func reachabilitySweep(hosts: [String]) -> [String] {
        guard !hosts.isEmpty else { return [] }
        var reachable = [Bool](repeating: false, count: hosts.count)
        let lock = NSLock()
        DispatchQueue.concurrentPerform(iterations: hosts.count) { index in
            let open = tcpOpen(ip: hosts[index], port: 80, timeout: 0.25)
                || tcpOpen(ip: hosts[index], port: 443, timeout: 0.25)
            if open {
                lock.lock()
                reachable[index] = true
                lock.unlock()
            }
        }
        return zip(hosts, reachable).filter { $0.1 }.map { $0.0 }
    }

    private static func tcpOpen(ip: String, port: UInt16, timeout: Double) -> Bool {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { return false }
        defer { close(descriptor) }

        let flags = fcntl(descriptor, F_GETFL, 0)
        _ = fcntl(descriptor, F_SETFL, flags | O_NONBLOCK)

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        guard inet_pton(AF_INET, ip, &address.sin_addr) == 1 else { return false }

        let status = withUnsafePointer(to: &address) { pointer -> Int32 in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                connect(descriptor, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if status == 0 { return true }
        guard errno == EINPROGRESS else { return false }

        var writeSet = fd_set()
        setBit(descriptor, in: &writeSet)
        var interval = timeval(tv_sec: 0, tv_usec: suseconds_t(timeout * 1_000_000))
        let selected = select(descriptor + 1, nil, &writeSet, nil, &interval)
        guard selected > 0 else { return false }

        var error: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &length) == 0 else { return false }
        return error == 0
    }

    private static func setBit(_ descriptor: Int32, in set: inout fd_set) {
        let offset = Int(descriptor / 32)
        let mask = Int32(1) << Int(descriptor % 32)
        withUnsafeMutablePointer(to: &set.fds_bits) { pointer in
            pointer.withMemoryRebound(to: Int32.self, capacity: 32) { bits in
                bits[offset] |= mask
            }
        }
    }

    // MARK: - Subnet math

    static func hostAddresses(ip: String, netmask: String) -> [String] {
        guard let value = ipv4Value(ip), let mask = ipv4Value(netmask) else { return [] }
        let prefixLength = mask.nonzeroBitCount
        guard prefixLength >= 16 else { return [] }
        // Keep the sweep bounded: never probe wider than a /24.
        let effectiveMask = prefixLength < 24 ? UInt32(0xFFFFFF00) : mask
        let network = value & effectiveMask
        let broadcast = network | ~effectiveMask
        guard broadcast > network + 2 else { return [] }

        var hosts: [String] = []
        var current = network + 1
        while current < broadcast {
            if current != value { hosts.append(ipv4String(current)) }
            current += 1
        }
        return hosts
    }

    static func prefixes(from interfaces: [LocalInterfaceInfo]) -> [String] {
        var result = Set<String>()
        for interface in interfaces {
            for address in interface.ipv6Global {
                guard let prefix = prefix64(address) else { continue }
                result.insert(prefix)
            }
        }
        return result.sorted()
    }

    private static func prefix64(_ address: String) -> String? {
        guard let percent = address.firstIndex(of: "%") else { return address + "/64" }
        let bare = String(address[address.startIndex..<percent])
        return bare + "/64"
    }

    private static func derivedGateway(from ip: String) -> String {
        guard var value = ipv4Value(ip) else { return ip }
        value = (value & 0xFFFFFF00) | 1
        return ipv4String(value)
    }

    private static func ipv4Value(_ string: String) -> UInt32? {
        var address = in_addr()
        guard inet_pton(AF_INET, string, &address) == 1 else { return nil }
        return UInt32(bigEndian: address.s_addr)
    }

    private static func ipv4String(_ value: UInt32) -> String {
        var address = in_addr(s_addr: value.bigEndian)
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        inet_ntop(AF_INET, &address, &buffer, socklen_t(INET_ADDRSTRLEN))
        return String(cString: buffer)
    }

    private static func isUnicast(_ ip: String) -> Bool {
        guard let value = ipv4Value(ip) else { return false }
        if value == 0 || value == 0xFFFFFFFF { return false }
        let firstOctet = (value >> 24) & 0xFF
        if firstOctet >= 224 { return false }
        if ip == "255.255.255.255" { return false }
        return true
    }
}

private extension LocalInterfaceInfo {
    var isTunnel: Bool {
        name.hasPrefix("utun") || name.hasPrefix("ipsec") || name.hasPrefix("tun")
    }
}
