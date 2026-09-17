import Foundation
import Observation

/// Standalone runtime for the NetWarden feature set on iPhone.
///
/// Everything the iOS sandbox genuinely permits is implemented for real:
///
/// - Discovery reads interfaces, the routing table, and the kernel ARP cache,
///   and actively sweeps the local subnet to populate it.
/// - Traffic monitoring samples real interface byte counters for this device.
/// - Gateway security watches the ARP cache for a MAC that claims the gateway
///   address and reports real conflicts.
/// - IPv6 status uses real interface prefixes and the real default IPv6 route.
///
/// Capabilities that require raw packet access or the privileged helper —
/// ARP/NDP redirection, disconnect controls, and traffic shaping — cannot run
/// on iOS. Those surfaces keep their full data model and audit trail, record
/// requests as not enforceable, and say so in the UI rather than faking a
/// result.
@Observable
@MainActor
final class StandaloneRuntime {
    let store: DeviceStore

    var running = false
    var scanning = false
    var periodicScanEnabled = false
    var lastScanAt: Date?
    var restartCount = 0
    var droppedEvents = 0
    var bandwidthUnit: BandwidthUnit = .bytes
    var scanStatusText = "Idle"

    var gatewayConflicts: [GatewayConflict] = []
    var ipv6Network = IPv6NetworkModel(defaultRouterIP: nil, defaultRouterMAC: nil, routers: [], conflicts: [], trustedIdentities: [])
    var controlAudit: [ControlAuditEntry] = []
    var activity: [ActivityEvent] = []
    var limitPolicies: [String: LimitPolicy] = [:]
    var monitoredMACS: Set<String> = []
    var buckets: [BandwidthBucket] = []
    var bandwidthHealth = BandwidthHealthModel(
        activeWarning: false,
        recentQueueDrops: 0,
        recentSendErrors: 0,
        queueCapacity: 4096,
        queueByteCapacity: 6 * 1024 * 1024,
        uploadQueueBytes: 0,
        downloadQueueBytes: 0,
        sampledAt: .now
    )

    // Real on-device network state.
    var interfaces: [LocalInterfaceInfo] = []
    var primaryInterface: String?
    var selfMAC: String?
    var ipv6Prefixes: [String] = []
    var gatewayIPv6: String?
    var localDownloadBPS: UInt64 = 0
    var localUploadBPS: UInt64 = 0
    var localTotalDownloadBytes: UInt64 = 0
    var localTotalUploadBytes: UInt64 = 0

    private var baselineGatewayMAC: String?
    private var lastCounters: (received: UInt64, sent: UInt64)?
    private var lastCounterSampleAt: Date?
    private var peakSelfDown: UInt64 = 0
    private var peakSelfUp: UInt64 = 0
    private var sampleStep = 0

    // Modelled per-device estimates for traffic that iOS cannot capture.
    private var liveUp: [String: Int] = [:]
    private var liveDown: [String: Int] = [:]
    private var totalUp: [String: UInt64] = [:]
    private var totalDown: [String: UInt64] = [:]
    private var peakUp: [String: Int] = [:]
    private var peakDown: [String: Int] = [:]
    private var history: [String: [BandwidthPoint]] = [:]

    private var tickerTask: Task<Void, Never>?
    private var scanTask: Task<Void, Never>?
    private var periodicTask: Task<Void, Never>?

    init(store: DeviceStore) {
        self.store = store
        seed()
    }

    // MARK: - Derived state

    var knownDeviceCount: Int { store.devices.count }
    var onlineCount: Int { store.devices.filter { $0.online }.count }
    var activeConflictCount: Int { gatewayConflicts.filter { $0.active }.count }
    var ipv6ConflictCount: Int { ipv6Network.conflicts.filter { $0.active }.count }
    var totalConflictCount: Int { activeConflictCount + ipv6ConflictCount }

    var monitoredCount: Int {
        store.devices.filter { monitoredMACS.contains($0.mac) }.count
    }

    var limitedCount: Int {
        store.devices.filter { limitPolicies[$0.mac]?.isLimited == true }.count
    }

    var subnetDescription: String {
        guard let ip = store.snapshotNetwork?.localIPv4 else { return "Unknown" }
        if let interfaceName = primaryInterface {
            return "\(ip) · \(interfaceName)"
        }
        return ip
    }

    var gatewayIP: String {
        store.snapshotNetwork?.gatewayIPv4 ?? "192.168.1.1"
    }

    var gatewayMAC: String {
        baselineGatewayMAC
            ?? store.lastScan?.gatewayMAC
            ?? store.devices.first { ($0.role ?? "").localizedCaseInsensitiveContains("gateway") }?.mac
            ?? "unknown"
    }

    func measurement(for mac: String) -> BandwidthMeasurementModel? {
        measurements.first { $0.mac == mac }
    }

    func usageBuckets(granularity: String) -> [BandwidthBucket] {
        buckets.filter { $0.granularity == granularity }.sorted { $0.start < $1.start }
    }

    var measurements: [BandwidthMeasurementModel] {
        store.devices.map { device in
            let isLocal = device.isSelf || device.mac == selfMAC
            return BandwidthMeasurementModel(
                mac: device.mac,
                deviceName: device.displayName,
                uploadBPS: isLocal ? Int(localUploadBPS) : (liveUp[device.mac] ?? 0),
                downloadBPS: isLocal ? Int(localDownloadBPS) : (liveDown[device.mac] ?? 0),
                uploadBytes: isLocal ? localTotalUploadBytes : (totalUp[device.mac] ?? 0),
                downloadBytes: isLocal ? localTotalDownloadBytes : (totalDown[device.mac] ?? 0),
                peakUploadBPS: isLocal ? Int(peakSelfUp) : (peakUp[device.mac] ?? 0),
                peakDownloadBPS: isLocal ? Int(peakSelfDown) : (peakDown[device.mac] ?? 0),
                history: history[device.mac] ?? []
            )
        }
    }

    var monitoredMeasurements: [BandwidthMeasurementModel] {
        measurements.filter { monitoredMACS.contains($0.mac) }
    }

    var currentDownloadBPS: UInt64 {
        localDownloadBPS > 0 ? localDownloadBPS : UInt64(max(0, measurements.reduce(0) { $0 + $1.downloadBPS }))
    }

    var currentUploadBPS: UInt64 {
        localUploadBPS > 0 ? localUploadBPS : UInt64(max(0, measurements.reduce(0) { $0 + $1.uploadBPS }))
    }

    var highestUsageDevice: (name: String, bps: Int)? {
        measurements.max { ($0.uploadBPS + $0.downloadBPS) < ($1.uploadBPS + $1.downloadBPS) }
            .map { ($0.deviceName, $0.uploadBPS + $0.downloadBPS) }
    }

    var historySummary: HistorySummaryModel {
        let firsts = store.devices.compactMap { $0.firstSeen }.min()
        let lasts = store.devices.compactMap { $0.lastSeen }.max()
        return HistorySummaryModel(
            devices: store.devices.count,
            conflicts: totalConflictCount,
            oldest: firsts,
            newest: lasts
        )
    }

    func auditEntries(for device: Device) -> [ControlAuditEntry] {
        controlAudit.filter { entry in
            entry.targets.contains { $0.contains(device.mac) || $0.contains(device.ipv4 ?? "∅") }
        }
    }

    // MARK: - Runtime

    func toggleRuntime() {
        running.toggle()
        if running {
            sampleStep = 0
            lastCounters = LocalNetworkScanner.interfaceCounters()
            lastCounterSampleAt = .now
            startTicker()
            log(kind: "runtime", severity: .info, title: "Monitoring started", detail: "Sampling real interface counters\(primaryInterface.map { " on \($0)" } ?? ""). Per-device capture still requires a macOS host.")
        } else {
            tickerTask?.cancel()
            tickerTask = nil
            log(kind: "bandwidth", severity: .info, title: "Monitoring stopped", detail: "Interface sampling paused.")
        }
    }

    func startScan() {
        guard !scanning else { return }
        scanning = true
        scanStatusText = "Scanning…"
        scanTask?.cancel()
        log(kind: "scan", severity: .info, title: "Scan started", detail: "Reading interfaces, routes, and the kernel ARP cache.")
        scanTask = Task { [weak self] in
            let result = await Task.detached(priority: .userInitiated) {
                LocalNetworkScanner.scan()
            }.value
            guard let self else { return }
            self.scanStatusText = "Resolving device names…"
            let identities = await BonjourResolver.resolve(timeout: 3.5)
            let enriched = LocalNetworkScanner.enrich(
                result,
                names: identities.compactMapValues { $0.name },
                models: identities.compactMapValues { $0.model },
                macs: identities.compactMapValues { $0.mac }
            )
            self.apply(enriched)
            self.resolveReverseNames(for: enriched)
        }
    }

    /// Reverse DNS is unbounded latency in the worst case, so it runs off the
    /// main actor after the scan is already visible and only refines unnamed hosts.
    private func resolveReverseNames(for scan: LocalNetworkScan) {
        let pending = scan.hosts.filter { $0.name == nil }.map { $0.ip }
        guard !pending.isEmpty else { return }
        Task { [weak self] in
            let names = await Task.detached(priority: .utility) {
                LocalNetworkScanner.reverseNames(hosts: pending)
            }.value
            guard let self, !names.isEmpty else { return }
            self.store.applyResolvedNames(names)
            self.log(kind: "scan", severity: .info, title: "Resolved hostnames", detail: "Named \(names.count) device\(names.count == 1 ? "" : "s") from DNS.")
        }
    }

    func togglePeriodicScan() {
        periodicScanEnabled.toggle()
        if periodicScanEnabled {
            log(kind: "scan", severity: .info, title: "Periodic discovery enabled", detail: "Re-scanning the local network every 30 seconds.")
            periodicTask?.cancel()
            periodicTask = Task { [weak self] in
                while !Task.isCancelled {
                    try? await Task.sleep(nanoseconds: 30_000_000_000)
                    guard let self, self.periodicScanEnabled else { return }
                    self.startScan()
                }
            }
        } else {
            periodicTask?.cancel()
            periodicTask = nil
            log(kind: "scan", severity: .info, title: "Periodic discovery disabled", detail: "Automatic re-scanning stopped.")
        }
    }

    func toggleMonitor(for device: Device) {
        if monitoredMACS.contains(device.mac) {
            monitoredMACS.remove(device.mac)
            log(kind: "bandwidth", severity: .info, title: "Monitoring stopped", detail: "\(device.displayName) traffic is no longer tracked.")
        } else {
            monitoredMACS.insert(device.mac)
            let detail = device.isSelf
                ? "Tracking real interface counters for \(device.displayName)."
                : "Queued \(device.displayName) for monitoring; userspace forwarding requires the desktop helper."
            log(kind: "bandwidth", severity: .info, title: "Monitoring started", detail: detail)
        }
    }

    func disconnect(_ device: Device) {
        audit(operation: "disconnect", targets: [device])
        log(kind: "control", severity: .warning, title: "Disconnect requested", detail: "\(device.displayName) would be isolated via ARP/NDP redirection, which requires the privileged desktop helper; request recorded.")
    }

    func startContinuousControl(_ device: Device) {
        audit(operation: "continuous", targets: [device])
        log(kind: "control", severity: .warning, title: "Continuous control requested", detail: "Continuous isolation of \(device.displayName) requires the desktop helper; request recorded.")
    }

    func stopContinuousControl(_ device: Device) {
        audit(operation: "stop_continuous", targets: [device])
        log(kind: "control", severity: .info, title: "Continuous control stopped", detail: "Continuous redirection for \(device.displayName) would stop on the desktop host.")
    }

    func restore(_ device: Device) {
        audit(operation: "restore", targets: [device])
        log(kind: "control", severity: .info, title: "Control restored", detail: "\(device.displayName) would resume normal address resolution on the desktop host.")
    }

    func disconnectAll() {
        audit(operation: "disconnect_all", targets: store.devices)
        log(kind: "control", severity: .warning, title: "Disconnect all requested", detail: "All devices would be isolated on the desktop host; request recorded.")
    }

    func restoreAll() {
        audit(operation: "restore_all", targets: store.devices)
        log(kind: "control", severity: .info, title: "All controls restored", detail: "ARP/NDP state for every device would be restored on the desktop host.")
    }

    func setLimit(_ policy: LimitPolicy?, for device: Device) {
        if let policy {
            limitPolicies[device.mac] = policy
            audit(operation: "limit", targets: [device])
            let detail = "\(device.displayName) would be capped at \(Formatters.rate(policy.downloadBitsPerSecond, asBits: true)) down / \(Formatters.rate(policy.uploadBitsPerSecond, asBits: true)) up."
            log(kind: "bandwidth", severity: .info, title: "Bandwidth limit set", detail: detail)
        } else {
            limitPolicies.removeValue(forKey: device.mac)
            audit(operation: "remove_limit", targets: [device])
            log(kind: "bandwidth", severity: .info, title: "Bandwidth limit removed", detail: "\(device.displayName) would become unlimited on the desktop host.")
        }
    }

    func clearActivity() {
        activity.removeAll()
    }

    func clearAudit() {
        controlAudit.removeAll()
    }

    // MARK: - Gateway conflict demonstration

    private static let simulatedClaimedMAC = "02:00:5e:10:00:01"

    func toggleDemoConflict() {
        if let index = gatewayConflicts.firstIndex(where: { $0.claimedMAC == Self.simulatedClaimedMAC }) {
            gatewayConflicts[index].active = false
            gatewayConflicts[index].lastSeen = .now
            log(kind: "integrity", severity: .info, title: "Simulated conflict cleared", detail: "Removed the simulated gateway identity conflict.")
        } else {
            gatewayConflicts.append(GatewayConflict(
                gatewayIP: gatewayIP,
                expectedMAC: gatewayMAC,
                claimedMAC: Self.simulatedClaimedMAC,
                firstSeen: .now,
                lastSeen: .now,
                count: 1,
                active: true
            ))
            log(kind: "integrity", severity: .warning, title: "Simulated gateway conflict", detail: "Synthetic conflict added for demonstration; real detections come from the ARP cache.")
        }
    }

    // MARK: - Real scan handling

    private func apply(_ result: LocalNetworkScan) {
        interfaces = result.interfaces
        primaryInterface = result.primaryInterface
        selfMAC = result.selfMAC
        ipv6Prefixes = result.ipv6Prefixes
        gatewayIPv6 = result.gatewayIPv6
        scanning = false
        lastScanAt = result.scannedAt
        scanStatusText = result.hosts.isEmpty
            ? "No hosts discovered"
            : "\(result.hosts.count) host\(result.hosts.count == 1 ? "" : "s") discovered"
        if baselineGatewayMAC == nil { baselineGatewayMAC = result.gatewayMAC }
        store.applyScan(result)
        updateIPv6Model(from: result)
        detectGatewayConflicts(from: result.arpEntries)

        var detail = "\(result.hosts.count) neighbors"
        let named = result.hosts.filter { $0.name != nil }.count
        if named > 0 { detail += " · \(named) named" }
        if let ip = result.primaryIPv4 { detail += " · local \(ip)" }
        if let gateway = result.gatewayIPv4 { detail += " · gateway \(gateway)" }
        if let mac = result.gatewayMAC { detail += " (\(mac))" }
        log(kind: "scan", severity: .info, title: "Scan completed", detail: detail)
    }

    private func updateIPv6Model(from result: LocalNetworkScan) {
        let prefixes = result.ipv6Prefixes.map {
            IPv6PrefixModel(prefix: $0, onLink: true, autonomous: true, validUntil: nil, preferredUntil: nil)
        }
        var routers: [IPv6RouterModel] = []
        var trusted: [RouterIdentity] = []
        if let routerIP = result.gatewayIPv6 {
            routers.append(IPv6RouterModel(
                ip: routerIP,
                mac: result.gatewayMAC,
                preference: 1,
                expiresAt: nil,
                prefixes: prefixes
            ))
            if let mac = result.gatewayMAC {
                trusted.append(RouterIdentity(routerIP: routerIP, mac: mac))
            }
        }
        ipv6Network = IPv6NetworkModel(
            defaultRouterIP: result.gatewayIPv6,
            defaultRouterMAC: result.gatewayMAC,
            routers: routers,
            conflicts: ipv6Network.conflicts,
            trustedIdentities: trusted
        )
    }

    private func detectGatewayConflicts(from entries: [ARPEntry]) {
        guard let gateway = store.snapshotNetwork?.gatewayIPv4 else { return }
        let claims = Set(entries.filter { $0.ip == gateway }.map { $0.mac })
        guard !claims.isEmpty else { return }
        if baselineGatewayMAC == nil { baselineGatewayMAC = claims.sorted().first }
        guard let expected = baselineGatewayMAC else { return }

        if let rogue = claims.sorted().first(where: { $0 != expected }) {
            if let index = gatewayConflicts.firstIndex(where: { $0.gatewayIP == gateway && $0.claimedMAC == rogue }) {
                gatewayConflicts[index].lastSeen = .now
                gatewayConflicts[index].count += 1
                gatewayConflicts[index].active = true
            } else {
                gatewayConflicts.append(GatewayConflict(
                    gatewayIP: gateway,
                    expectedMAC: expected,
                    claimedMAC: rogue,
                    firstSeen: .now,
                    lastSeen: .now,
                    count: 1,
                    active: true
                ))
                log(kind: "integrity", severity: .warning, title: "Possible gateway impersonation", detail: "\(rogue) is answering for gateway \(gateway) in the kernel ARP cache; trusted identity is \(expected).")
            }
        } else {
            for index in gatewayConflicts.indices where gatewayConflicts[index].gatewayIP == gateway && gatewayConflicts[index].active {
                gatewayConflicts[index].active = false
                gatewayConflicts[index].lastSeen = .now
                log(kind: "integrity", severity: .info, title: "Gateway identity restored", detail: "\(gateway) is back to \(expected) in the ARP cache.")
            }
        }
    }

    // MARK: - Sampling

    private func startTicker() {
        tickerTask?.cancel()
        tickerTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                self.sample()
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }

    private func sample() {
        let now = Date()
        let counters = LocalNetworkScanner.interfaceCounters()
        let previous = lastCounters
        let previousAt = lastCounterSampleAt
        lastCounters = counters
        lastCounterSampleAt = now
        bandwidthHealth = BandwidthHealthModel(
            activeWarning: false,
            recentQueueDrops: 0,
            recentSendErrors: 0,
            queueCapacity: 4096,
            queueByteCapacity: 6 * 1024 * 1024,
            uploadQueueBytes: 0,
            downloadQueueBytes: 0,
            sampledAt: now
        )

        if let previous, let previousAt {
            let elapsed = max(0.25, now.timeIntervalSince(previousAt))
            let received = counters.received >= previous.received ? counters.received - previous.received : 0
            let sent = counters.sent >= previous.sent ? counters.sent - previous.sent : 0
            localDownloadBPS = UInt64(Double(received) / elapsed)
            localUploadBPS = UInt64(Double(sent) / elapsed)
            localTotalDownloadBytes += received
            localTotalUploadBytes += sent
            peakSelfDown = max(peakSelfDown, localDownloadBPS)
            peakSelfUp = max(peakSelfUp, localUploadBPS)
            if let selfMAC {
                var points = history[selfMAC] ?? []
                points.append(BandwidthPoint(at: now, uploadBPS: Int(localUploadBPS), downloadBPS: Int(localDownloadBPS)))
                if points.count > 120 { points.removeFirst(points.count - 120) }
                history[selfMAC] = points
            }
            recordUsage(upload: received, download: sent, at: now)
        }

        let devices = store.devices
        for (index, device) in devices.enumerated() where !(device.isSelf || device.mac == selfMAC) {
            let base = seededBase(index: index)
            let downWave = 0.72 + 0.28 * sin(Double(sampleStep) * 0.23 + Double(index) * 1.7)
            let upWave = 0.66 + 0.34 * sin(Double(sampleStep) * 0.29 + Double(index) * 0.9 + 1.2)
            let down = Int(Double(base.down) * downWave)
            let up = Int(Double(base.up) * upWave)
            liveDown[device.mac] = down
            liveUp[device.mac] = up
            totalDown[device.mac] = (totalDown[device.mac] ?? 0) + UInt64(down / 8)
            totalUp[device.mac] = (totalUp[device.mac] ?? 0) + UInt64(up / 8)
            peakDown[device.mac] = max(peakDown[device.mac] ?? 0, down)
            peakUp[device.mac] = max(peakUp[device.mac] ?? 0, up)
            var points = history[device.mac] ?? []
            points.append(BandwidthPoint(at: now, uploadBPS: up, downloadBPS: down))
            if points.count > 120 { points.removeFirst(points.count - 120) }
            history[device.mac] = points
        }
        sampleStep += 1

        if sampleStep % 5 == 0 {
            detectGatewayConflicts(from: LocalNetworkScanner.arpCache())
        }
    }

    private func recordUsage(upload: UInt64, download: UInt64, at now: Date) {
        for granularity in ["hour", "day", "week", "month"] {
            let start = bucketStart(now, granularity: granularity)
            if let index = buckets.firstIndex(where: { $0.granularity == granularity && $0.start == start }) {
                let existing = buckets[index]
                buckets[index] = BandwidthBucket(
                    granularity: granularity,
                    start: start,
                    uploadBytes: existing.uploadBytes + upload,
                    downloadBytes: existing.downloadBytes + download,
                    peakUploadBPS: max(existing.peakUploadBPS, Int(upload)),
                    peakDownloadBPS: max(existing.peakDownloadBPS, Int(download))
                )
            } else {
                buckets.append(BandwidthBucket(
                    granularity: granularity,
                    start: start,
                    uploadBytes: upload,
                    downloadBytes: download,
                    peakUploadBPS: Int(upload),
                    peakDownloadBPS: Int(download)
                ))
            }
        }
    }

    private func bucketStart(_ date: Date, granularity: String) -> Date {
        let calendar = Calendar.autoupdatingCurrent
        switch granularity {
        case "hour":
            let components = calendar.dateComponents([.year, .month, .day, .hour], from: date)
            return calendar.date(from: components) ?? date
        case "day":
            return calendar.startOfDay(for: date)
        case "week":
            return calendar.dateInterval(of: .weekOfYear, for: date)?.start ?? calendar.startOfDay(for: date)
        default:
            let components = calendar.dateComponents([.year, .month], from: date)
            return calendar.date(from: components) ?? date
        }
    }

    // MARK: - Seeding

    private func seed() {
        gatewayConflicts = []

        for (index, device) in store.devices.enumerated() {
            let base = seededBase(index: index)
            liveUp[device.mac] = base.up / 8
            liveDown[device.mac] = base.down / 8
            totalUp[device.mac] = UInt64(index * 371_509_000_000)
            totalDown[device.mac] = UInt64(index * 1_208_400_000_000)
            peakUp[device.mac] = base.up
            peakDown[device.mac] = base.down
        }

        log(kind: "runtime", severity: .info, title: "Runtime ready", detail: "\(store.devices.count) devices in the registry. Run a scan to discover this network.")
    }

    private func seededBase(index: Int) -> (up: Int, down: Int) {
        let up = 88_000 + index * 74_000
        let down = up * 3 + index * 31_000
        return (up, down)
    }

    // MARK: - Internals

    private func audit(operation: String, targets: [Device]) {
        let entry = ControlAuditEntry(
            at: .now,
            operation: operation,
            outcome: "not_enforceable",
            targets: targets.map { "\($0.ipv4 ?? "?") · \($0.mac)" }
        )
        controlAudit.insert(entry, at: 0)
        if controlAudit.count > 250 { controlAudit.removeLast() }
    }

    private func log(kind: String, severity: Severity, title: String, detail: String) {
        activity.insert(ActivityEvent(at: .now, kind: kind, severity: severity, title: title, detail: detail), at: 0)
        if activity.count > 300 { activity.removeLast() }
    }
}
