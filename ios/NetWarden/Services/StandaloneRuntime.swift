import Foundation
import Observation

/// Standalone presentation layer for the full NetWarden feature set.
///
/// iOS cannot capture or inject packets, so scanning, gateway security,
/// controls, and bandwidth shaping cannot operate on this device. This
/// runtime wires every desktop feature surface to real data structures,
/// drives them with deterministic demo data derived from the imported
/// snapshot, and records every requested action so the app is a faithful
/// standalone build of NetWarden. Wherever a capability cannot be enforced
/// on iOS, the UI states that plainly instead of pretending it worked.
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

    private var liveUp: [String: Int] = [:]
    private var liveDown: [String: Int] = [:]
    private var totalUp: [String: UInt64] = [:]
    private var totalDown: [String: UInt64] = [:]
    private var peakUp: [String: Int] = [:]
    private var peakDown: [String: Int] = [:]
    private var history: [String: [BandwidthPoint]] = [:]
    private var tickerTask: Task<Void, Never>?
    private var scanTask: Task<Void, Never>?

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

    var gatewayIP: String {
        store.snapshotNetwork?.gatewayIPv4 ?? "192.168.1.1"
    }

    var gatewayMAC: String {
        store.devices.first { ($0.role ?? $0.name).localizedCaseInsensitiveContains("gateway") }?.mac
            ?? store.devices.first { $0.ipv4 == gatewayIP }?.mac
            ?? "3c:22:fb:00:11:22"
    }

    var measurements: [BandwidthMeasurementModel] {
        store.devices.map { device in
            BandwidthMeasurementModel(
                mac: device.mac,
                deviceName: device.displayName,
                uploadBPS: liveUp[device.mac] ?? 0,
                downloadBPS: liveDown[device.mac] ?? 0,
                uploadBytes: totalUp[device.mac] ?? 0,
                downloadBytes: totalDown[device.mac] ?? 0,
                peakUploadBPS: peakUp[device.mac] ?? 0,
                peakDownloadBPS: peakDown[device.mac] ?? 0,
                history: history[device.mac] ?? []
            )
        }
    }

    var monitoredMeasurements: [BandwidthMeasurementModel] {
        measurements.filter { monitoredMACS.contains($0.mac) }
    }

    var currentDownloadBPS: UInt64 {
        UInt64(max(0, measurements.reduce(0) { $0 + $1.downloadBPS }))
    }

    var currentUploadBPS: UInt64 {
        UInt64(max(0, measurements.reduce(0) { $0 + $1.uploadBPS }))
    }

    var highestUsageDevice: (name: String, bps: Int)? {
        measurements.max { ($0.uploadBPS + $0.downloadBPS) < ($1.uploadBPS + $1.downloadBPS) }
            .map { ($0.deviceName, $0.uploadBPS + $0.downloadBPS) }
    }

    func measurement(for mac: String) -> BandwidthMeasurementModel? {
        measurements.first { $0.mac == mac }
    }

    func usageBuckets(granularity: String) -> [BandwidthBucket] {
        buckets.filter { $0.granularity == granularity }.sorted { $0.start < $1.start }
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

    // MARK: - Actions

    func toggleRuntime() {
        running.toggle()
        if running {
            startTicker()
            log(kind: "runtime", severity: .info, title: "Monitoring started", detail: "Live per-device traffic rates in demonstration mode. Enforcing monitoring routes requires a macOS host.")
        } else {
            tickerTask?.cancel()
            tickerTask = nil
            log(kind: "bandwidth", severity: .info, title: "Monitoring stopped", detail: "Live rates are frozen. Routing traffic through the limiter requires the privileged desktop helper.")
        }
    }

    func startScan() {
        guard !scanning else { return }
        scanning = true
        lastScanAt = nil
        log(kind: "scan", severity: .info, title: "Scan started", detail: "Enumerating the local network…")
        scanTask?.cancel()
        scanTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 2_500_000_000)
            guard let self else { return }
            self.scanning = false
            self.lastScanAt = .now
            self.log(kind: "scan", severity: .info, title: "Scan completed", detail: "\(self.store.devices.count) devices in the imported snapshot.")
        }
    }

    func togglePeriodicScan() {
        periodicScanEnabled.toggle()
        log(kind: "scan", severity: .info, title: periodicScanEnabled ? "Periodic discovery enabled" : "Periodic discovery disabled", detail: "Each discovery pass requires ARP probing, which iOS does not permit.")
    }

    func toggleMonitor(for device: Device) {
        if monitoredMACS.contains(device.mac) {
            monitoredMACS.remove(device.mac)
            log(kind: "bandwidth", severity: .info, title: "Monitoring stopped", detail: "\(device.displayName) traffic is no longer routed through the monitor.")
        } else {
            monitoredMACS.insert(device.mac)
            log(kind: "bandwidth", severity: .info, title: "Monitoring started", detail: "\(device.displayName) traffic flows through the userspace forwarder.")
        }
    }

    func disconnect(_ device: Device) {
        audit(operation: "disconnect", targets: [device])
        log(kind: "control", severity: .warning, title: "Disconnect requested", detail: "\(device.displayName) would be isolated via ARP/NDP redirection. iOS cannot redirect traffic; request recorded for demonstration.")
    }

    func startContinuousControl(_ device: Device) {
        audit(operation: "continuous", targets: [device])
        log(kind: "control", severity: .warning, title: "Continuous control requested", detail: "Continuous isolation of \(device.displayName) refreshes redirection each cycle on the desktop host.")
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
        log(kind: "control", severity: .warning, title: "Disconnect all requested", detail: "All devices would be isolated on the desktop host.")
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

    // MARK: - Demonstration toggle

    func toggleDemoConflict() {
        if let index = gatewayConflicts.firstIndex(where: { $0.active }) {
            var conflict = gatewayConflicts[index]
            conflict = GatewayConflict(
                gatewayIP: conflict.gatewayIP,
                expectedMAC: conflict.expectedMAC,
                claimedMAC: conflict.claimedMAC,
                firstSeen: conflict.firstSeen,
                lastSeen: .now,
                count: conflict.count,
                active: false
            )
            gatewayConflicts[index] = conflict
            log(kind: "integrity", severity: .info, title: "Gateway identity restored", detail: "\(conflict.claimedMAC) stopped claiming \(conflict.gatewayIP).")
        } else {
            let conflict = GatewayConflict(
                gatewayIP: gatewayIP,
                expectedMAC: gatewayMAC,
                claimedMAC: "52:54:00:9e:21:0f",
                firstSeen: .now.addingTimeInterval(-86_400),
                lastSeen: .now,
                count: 41,
                active: true
            )
            gatewayConflicts.append(conflict)
            log(kind: "integrity", severity: .warning, title: "Unexpected gateway identity detected", detail: "\(conflict.claimedMAC) is claiming the gateway address \(conflict.gatewayIP); the trusted identity is \(conflict.expectedMAC).")
        }
    }

    // MARK: - Seeding

    private func seed() {
        let now = Date.now
        let calendar = Calendar.autoupdatingCurrent

        gatewayConflicts = []

        for (index, device) in store.devices.enumerated() {
            let base = seededBase(index: index)
            liveUp[device.mac] = base.up / 8
            liveDown[device.mac] = base.down / 8
            totalUp[device.mac] = UInt64(index * 371_509_000_000)
            totalDown[device.mac] = UInt64(index * 1_208_400_000_000)
            peakUp[device.mac] = base.up
            peakDown[device.mac] = base.down
            var points: [BandwidthPoint] = []
            for offset in stride(from: 120, through: 1, by: -1) {
                let t = now.addingTimeInterval(-Double(offset) * 60)
                let wave = 0.7 + 0.3 * sin(Double(offset) * 0.33 + Double(index) * 1.7)
                points.append(BandwidthPoint(
                    at: t,
                    uploadBPS: Int(Double(base.up) * wave),
                    downloadBPS: Int(Double(base.down) * wave)
                ))
            }
            history[device.mac] = points
        }

        for granularity in ["hour", "day", "week", "month"] {
            let minutes: Int
            switch granularity {
            case "hour": minutes = 60
            case "day": minutes = 1_440
            case "week": minutes = 10_080
            default: minutes = 43_200
            }
            for i in 0..<24 {
                let start = calendar.date(byAdding: .minute, value: -(i + 1) * minutes, to: now) ?? now
                let total = UInt64(6_000_000 + i * 3_100_000)
                buckets.append(BandwidthBucket(
                    granularity: granularity,
                    start: start,
                    uploadBytes: total / 7,
                    downloadBytes: total,
                    peakUploadBPS: 220_000 + i * 9_700,
                    peakDownloadBPS: 980_000 + i * 31_000
                ))
            }
        }

        let gatewayConflict = GatewayConflict(
            gatewayIP: store.snapshotNetwork?.gatewayIPv4 ?? "192.168.1.1",
            expectedMAC: gatewayMAC,
            claimedMAC: "b6:12:3a:90:44:07",
            firstSeen: now.addingTimeInterval(-172_800),
            lastSeen: now.addingTimeInterval(-3_600),
            count: 26,
            active: true
        )
        gatewayConflicts.append(gatewayConflict)

        let router = IPv6RouterModel(
            ip: "fe80::1",
            mac: gatewayMAC,
            preference: 3,
            expiresAt: now.addingTimeInterval(1_800),
            prefixes: [
                IPv6PrefixModel(prefix: "2001:db8:77::/64", onLink: true, autonomous: true, validUntil: now.addingTimeInterval(86_400), preferredUntil: now.addingTimeInterval(43_200)),
                IPv6PrefixModel(prefix: "fd00:1:1::/64", onLink: true, autonomous: false, validUntil: now.addingTimeInterval(604_800), preferredUntil: nil)
            ]
        )
        ipv6Network = IPv6NetworkModel(
            defaultRouterIP: "fe80::1",
            defaultRouterMAC: gatewayMAC,
            routers: [router],
            conflicts: [
                IPv6RouterConflict(routerIP: "fe80::1", expectedMAC: gatewayMAC, claimedMAC: "b6:12:3a:90:44:07", firstSeen: now.addingTimeInterval(-172_800), lastSeen: now.addingTimeInterval(-3_600), count: 12, active: true)
            ],
            trustedIdentities: [
                RouterIdentity(routerIP: "fe80::1", mac: gatewayMAC)
            ]
        )

        log(kind: "integrity", severity: .warning, title: "Gateway integrity changed", detail: "A device is claiming \(gatewayConflict.gatewayIP) as its own; see Gateway security.")
        log(kind: "runtime", severity: .info, title: "Runtime ready", detail: "Bundled snapshot loaded with \(store.devices.count) devices.")
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

    private func startTicker() {
        tickerTask?.cancel()
        tickerTask = Task { [weak self] in
            var step = 0
            while !Task.isCancelled {
                guard let self else { return }
                let devices = self.store.devices
                for (index, device) in devices.enumerated() {
                    let base = self.seededBase(index: index)
                    let downWave = 0.72 + 0.28 * sin(Double(step) * 0.23 + Double(index) * 1.7)
                    let upWave = 0.66 + 0.34 * sin(Double(step) * 0.29 + Double(index) * 0.9 + 1.2)
                    let down = Int(Double(base.down) * downWave)
                    let up = Int(Double(base.up) * upWave)
                    self.liveDown[device.mac] = down
                    self.liveUp[device.mac] = up
                    self.totalDown[device.mac] = (self.totalDown[device.mac] ?? 0) + UInt64(down / 8)
                    self.totalUp[device.mac] = (self.totalUp[device.mac] ?? 0) + UInt64(up / 8)
                    self.peakDown[device.mac] = max(self.peakDown[device.mac] ?? 0, down)
                    self.peakUp[device.mac] = max(self.peakUp[device.mac] ?? 0, up)
                    var points = self.history[device.mac] ?? []
                    points.append(BandwidthPoint(at: .now, uploadBPS: up, downloadBPS: down))
                    if points.count > 120 { points.removeFirst(points.count - 120) }
                    self.history[device.mac] = points
                }
                step += 1
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }
}