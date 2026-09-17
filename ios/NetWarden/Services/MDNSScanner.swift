import Foundation
import Network
import Observation

struct DiscoveredService: Identifiable, Hashable {
    let name: String
    let type: String
    let domain: String
    let interfaceNames: [String]

    var id: String { "\(type)|\(domain)|\(name)|\(interfaceNames.joined(separator: ","))" }
}

struct ServiceGroup: Identifiable {
    var id: String { type }

    let type: String
    let services: [DiscoveredService]
}

@Observable
@MainActor
final class MDNSScanner {
    private(set) var services: [DiscoveredService] = []
    private(set) var isScanning = false
    private(set) var statusMessage = "Ready"

    private var browsers: [NWBrowser] = []

    private static let serviceTypes = [
        "_http._tcp",
        "_printer._tcp",
        "_ipp._tcp",
        "_airplay._tcp",
        "_raop._tcp",
        "_companion-link._tcp",
        "_ssh._tcp",
        "_smb._tcp",
        "_spotify-connect._tcp",
    ]

    var sortedGroups: [ServiceGroup] {
        let grouped = Dictionary(grouping: services, by: { $0.type })
        return grouped
            .map { ServiceGroup(type: $0.key, services: $0.value.sorted { $0.name < $1.name }) }
            .sorted { $0.type < $1.type }
    }

    var servicesCount: Int { services.count }

    func start() {
        guard !isScanning, browsers.isEmpty else { return }
        isScanning = true
        statusMessage = "Browsing services…"

        let parameters = NWParameters()
        parameters.includePeerToPeer = true

        for type in Self.serviceTypes {
            let browser = NWBrowser(for: .bonjour(type: type, domain: nil), using: parameters)
            browser.stateUpdateHandler = { [weak self] state in
                Task { @MainActor [weak self] in
                    self?.handle(state, for: type)
                }
            }
            browser.browseResultsChangedHandler = { [weak self] results, _ in
                let mapped = results.map { result in
                    DiscoveredService(
                        name: serviceDisplayName(for: result.endpoint),
                        type: type,
                        domain: serviceDomain(for: result.endpoint),
                        interfaceNames: result.interfaces.map { $0.name }
                    )
                }
                Task { @MainActor [weak self] in
                    self?.replace(mapped, for: type)
                }
            }
            browser.start(queue: .main)
            browsers.append(browser)
        }
    }

    func stop() {
        for browser in browsers {
            browser.cancel()
        }
        browsers.removeAll()
        isScanning = false
        statusMessage = "Stopped"
    }

    private func handle(_ state: NWBrowser.State, for type: String) {
        let message: String
        switch state {
        case .ready:
            message = "Browsing services…"
        case .failed(let error):
            message = "\(type) failed: \(error.localizedDescription)"
        case .waiting(let error):
            message = "\(type) waiting: \(error.localizedDescription)"
        case .setup, .cancelled:
            message = "Browsing services…"
        @unknown default:
            message = "Browsing services…"
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            self.statusMessage = message
            if case .failed = state {
                self.isScanning = false
            }
        }
    }

    private func replace(_ incoming: [DiscoveredService], for type: String) {
        services.removeAll { $0.type == type }
        services.append(contentsOf: incoming)
        statusMessage = "\(services.count) service instance\(services.count == 1 ? "" : "s") found"
    }
}

private func serviceDomain(for endpoint: NWEndpoint) -> String {
    if case .service(_, _, let domain, _) = endpoint {
        return domain
    }
    return ""
}

private func serviceDisplayName(for endpoint: NWEndpoint) -> String {
    if case .service(let name, _, _, _) = endpoint {
        return name
    }
    return "\(endpoint)"
}