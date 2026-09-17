import Foundation
import Darwin

/// A real device identity learned from a Bonjour/mDNS advertisement.
struct BonjourIdentity: Hashable {
    var name: String?
    var model: String?
    var mac: String?
    var serviceType: String?
}

/// Resolves Bonjour services on the local link into address-keyed identities.
///
/// iOS cannot read hostnames through raw sockets, but mDNS is the mechanism
/// devices actually use to publish their names, models, and hardware IDs on a
/// LAN. This browses the common service types, resolves each advertisement, and
/// maps the advertised addresses (plus the TXT `deviceid`) to real names and
/// models.
final class BonjourResolver: NSObject {
    private static let serviceTypes = [
        "_device-info._tcp.",
        "_airplay._tcp.",
        "_raop._tcp.",
        "_companion-link._tcp.",
        "_workstation._tcp.",
        "_http._tcp.",
        "_https._tcp.",
        "_ipp._tcp.",
        "_printer._tcp.",
        "_scanner._tcp.",
        "_smb._tcp.",
        "_afpovertcp._tcp.",
        "_ssh._tcp.",
        "_rfb._tcp.",
        "_googlecast._tcp.",
        "_homekit._tcp.",
        "_hap._tcp.",
        "_apple-mobdev2._tcp."
    ]

    private let lock = NSLock()
    private var browsers: [NetServiceBrowser] = []
    private var services: [NetService] = []
    private var identities: [String: BonjourIdentity] = [:]
    private var seen: Set<String> = []

    /// Browses for `timeout` seconds and returns what was learned. NetService runs
    /// on the main run loop, so this keeps the UI responsive while advertisements
    /// arrive and returns whatever resolved before the deadline.
    static func resolve(timeout: TimeInterval = 3.5) async -> [String: BonjourIdentity] {
        let resolver = BonjourResolver()
        resolver.start()
        try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
        resolver.stop()
        return resolver.results()
    }

    private func results() -> [String: BonjourIdentity] {
        lock.lock()
        defer { lock.unlock() }
        return identities
    }

    /// Must be called from the main thread; `resolve()` does so via its caller.
    private func start() {
        for type in Self.serviceTypes {
            let browser = NetServiceBrowser()
            browser.delegate = self
            browser.schedule(in: .main, forMode: .common)
            browser.searchForServices(ofType: type, inDomain: "local.")
            browsers.append(browser)
        }
    }

    private func stop() {
        let active = browsers
        browsers.removeAll()
        for browser in active { browser.stop() }
    }

    private func register(_ service: NetService) {
        let key = "\(service.type)|\(service.name)|\(service.domain)"
        lock.lock()
        let isNew = seen.insert(key).inserted
        lock.unlock()
        guard isNew else { return }
        service.delegate = self
        services.append(service)
        service.resolve(withTimeout: 2.5)
    }

    private func record(type: String, instance: String, host: String?, model: String?, mac: String?, addresses: [String]) {
        let instanceName = Self.displayName(from: instance)
        let hostName = Self.hostName(from: host)
        lock.lock()
        for address in addresses {
            var identity = identities[address] ?? BonjourIdentity()
            if identity.name == nil { identity.name = instanceName ?? hostName }
            if identity.model == nil { identity.model = model }
            if identity.mac == nil { identity.mac = mac }
            if identity.serviceType == nil { identity.serviceType = type.trimmingCharacters(in: CharacterSet(charactersIn: ".")) }
            identities[address] = identity
        }
        lock.unlock()
    }

    private static func displayName(from instance: String) -> String? {
        var name = instance
        if let at = name.firstIndex(of: "@") { name = String(name[name.index(after: at)...]) }
        name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, !isHardwareIdentifier(name) else { return nil }
        return name
    }

    private static func hostName(from host: String?) -> String? {
        guard var name = host, !name.isEmpty else { return nil }
        if name.hasSuffix(".") { name = String(name.dropLast()) }
        if name.hasSuffix(".local") { name = String(name.dropLast(6)) }
        return name.isEmpty ? nil : name
    }

    private static func isHardwareIdentifier(_ value: String) -> Bool {
        let hexDigits = value.filter { $0.isHexDigit }
        let allowed = value.filter { $0.isHexDigit || $0 == ":" || $0 == "-" }
        return hexDigits.count >= 12 && allowed.count == value.count
    }

    private static func numericAddress(from data: Data) -> String? {
        guard data.count >= MemoryLayout<sockaddr>.size else { return nil }
        var storage = sockaddr_storage()
        let copied = withUnsafeMutableBytes(of: &storage) { destination -> Int in
            data.copyBytes(to: destination, count: min(data.count, MemoryLayout<sockaddr_storage>.size))
        }
        guard copied > 0 else { return nil }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let status = withUnsafePointer(to: &storage) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                getnameinfo(socketAddress, socklen_t(copied), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
            }
        }
        guard status == 0 else { return nil }
        let address = String(cString: host)
        return address.isEmpty ? nil : address
    }

    private static func normalizedMAC(_ value: String) -> String? {
        let hex = value.filter { $0.isHexDigit }.lowercased()
        guard hex.count == 12 else { return nil }
        var pairs: [String] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            pairs.append(String(hex[index..<next]))
            index = next
        }
        return pairs.joined(separator: ":")
    }
}

extension BonjourResolver: NetServiceBrowserDelegate {
    func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
        register(service)
    }

    func netServiceBrowser(_ browser: NetServiceBrowser, didRemove service: NetService, moreComing: Bool) {}

    func netServiceBrowser(_ browser: NetServiceBrowser, didNotSearch errorDict: [String: NSNumber]) {}
}

extension BonjourResolver: NetServiceDelegate {
    func netServiceDidResolveAddress(_ sender: NetService) {
        var model: String?
        var mac: String?
        if let record = sender.txtRecordData() {
            let values = NetService.dictionary(fromTXTRecord: record)
            if let data = values["model"] { model = String(data: data, encoding: .utf8) }
            if let data = values["deviceid"] { mac = Self.normalizedMAC(String(data: data, encoding: .utf8) ?? "") }
        }
        let addresses = (sender.addresses ?? []).compactMap { Self.numericAddress(from: $0) }
        guard !addresses.isEmpty else { return }
        record(type: sender.type, instance: sender.name, host: sender.hostName, model: model, mac: mac, addresses: addresses)
    }

    func netService(_ sender: NetService, didNotResolve errorDict: [String: NSNumber]) {}
}
