import SwiftUI
import Charts

struct BandwidthView: View {
    @Environment(StandaloneRuntime.self) private var runtime
    @State private var granularity = "hour"
    private let granularities = ["hour", "day", "week", "month"]

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    if !runtime.running {
                        idleNotice
                    }
                    summaryCard
                    healthCard
                    devicesCard
                    historyCard
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
            }
            .background(AppBackground())
            .navigationTitle("Bandwidth")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Picker("Unit", selection: Bindable(runtime).bandwidthUnit) {
                            ForEach(BandwidthUnit.allCases) { unit in
                                Text(unit.rawValue).tag(unit)
                            }
                        }
                    } label: {
                        Image(systemName: "chart.bar.xaxis")
                    }
                }
            }
        }
    }

    private var idleNotice: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "pause.circle.fill")
                .font(.title3)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 3) {
                Text("Monitoring inactive")
                    .font(.subheadline)
                Text("Start monitoring from the Network tab to see live rates. Enforcing monitoring routes requires the desktop app; iOS shows the shapes NetWarden reports.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .glassPanel(cornerRadius: 18)
    }

    private var summaryCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            PanelHeader(systemImage: "speedometer", title: "Traffic visibility", subtitle: "Live per-device rates, totals, and peaks", tag: "Experimental")
            LazyVGrid(columns: [GridItem(.flexible(), spacing: 12), GridItem(.flexible())], spacing: 12) {
                summaryTile(title: "Current download", value: Formatters.rate(runtime.currentDownloadBPS, asBits: runtime.bandwidthUnit == .bits), icon: "arrow.down")
                summaryTile(title: "Current upload", value: Formatters.rate(runtime.currentUploadBPS, asBits: runtime.bandwidthUnit == .bits), icon: "arrow.up")
                summaryTile(title: "Highest current usage", value: runtime.highestUsageDevice?.name ?? "—", icon: "chart.line.uptrend.xyaxis")
                summaryTile(title: "Monitored devices", value: "\(runtime.monitoredCount)", icon: "eye")
            }
        }
        .padding(18)
        .glassPanel()
    }

    private func summaryTile(title: String, value: String, icon: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: icon)
                    .font(.caption)
                    .foregroundStyle(.tint)
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text(value)
                .font(.title3.weight(.semibold))
                .lineLimit(1)
                .minimumScaleFactor(0.6)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassPanel(cornerRadius: 16)
    }

    private var healthCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            PanelHeader(systemImage: "waveform.path.ecg", title: "Forwarding health", subtitle: "Sampled at \(Formatters.shortTime(runtime.bandwidthHealth.sampledAt))", tag: "Experimental")
            HStack(spacing: 8) {
                Label(runtime.bandwidthHealth.statusLabel, systemImage: runtime.bandwidthHealth.activeWarning ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                    .font(.footnote)
                    .foregroundStyle(runtime.bandwidthHealth.activeWarning ? Color.orange : Color.green)
                Spacer()
            }
            InfoRow(label: "Recent queue drops", value: "\(runtime.bandwidthHealth.recentQueueDrops)")
            InfoRow(label: "Recent send errors", value: "\(runtime.bandwidthHealth.recentSendErrors)")
            InfoRow(label: "Queue capacity", value: "\(runtime.bandwidthHealth.queueCapacity) packets / \(Formatters.bytes(UInt64(runtime.bandwidthHealth.queueByteCapacity)))")
            InfoRow(label: "Queue occupancy", value: "\(Formatters.bytes(UInt64(runtime.bandwidthHealth.downloadQueueBytes))) ↓ / \(Formatters.bytes(UInt64(runtime.bandwidthHealth.uploadQueueBytes))) ↑")
            Text("Shaping routes packets through a userspace forwarder on the desktop host; queue pressure is reported here for parity.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(18)
        .glassPanel()
    }

    private var devicesCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            PanelHeader(systemImage: "rectangle.stack.badge.person.crop", title: "Devices", subtitle: "Monitoring routes remain active only while monitoring is running.", tag: "Experimental")
            ForEach(runtime.measurements) { measurement in
                BandwidthDeviceRow(measurement: measurement, unit: runtime.bandwidthUnit)
                if measurement.id != runtime.measurements.last?.id {
                    Divider()
                }
            }
        }
        .padding(18)
        .glassPanel()
    }

    private var historyCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            PanelHeader(systemImage: "clock.arrow.circlepath", title: "Usage history", subtitle: "Persistent compact usage buckets", tag: "Experimental")
            Picker("Granularity", selection: $granularity) {
                ForEach(granularities, id: \.self) { value in
                    Text(value.capitalized).tag(value)
                }
            }
            .pickerStyle(.segmented)
            let selected = runtime.usageBuckets(granularity: granularity)
            if selected.isEmpty {
                Text("No usage buckets for this range")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                Chart(selected) { bucket in
                    let download = Int(bucket.downloadBytes)
                    let upload = Int(bucket.uploadBytes)
                    BarMark(
                        x: .value("Time", bucket.start),
                        yStart: .value("Base", 0),
                        yEnd: .value("Download", download)
                    )
                    .foregroundStyle(Color.blue.gradient)
                    BarMark(
                        x: .value("Time", bucket.start),
                        yStart: .value("Download", download),
                        yEnd: .value("Upload", download + upload)
                    )
                    .foregroundStyle(Color.green.gradient)
                }
                .frame(height: 180)
                .chartYAxis {
                    AxisMarks { value in
                        AxisGridLine()
                        AxisValueLabel {
                            if let v = value.as(Int.self) {
                                Text(Formatters.bytes(UInt64(max(0, v))))
                                    .font(.caption2)
                            }
                        }
                    }
                }
                .chartXAxis {
                    AxisMarks(values: .automatic(desiredCount: 4)) { _ in
                        AxisValueLabel(format: .dateTime.month().day())
                    }
                }
                HStack(spacing: 14) {
                    Label("Download", systemImage: "square.fill")
                        .font(.caption)
                        .foregroundStyle(.blue)
                    Label("Upload", systemImage: "square.fill")
                        .font(.caption)
                        .foregroundStyle(.green)
                }
            }
        }
        .padding(18)
        .glassPanel()
    }
}

struct BandwidthDeviceRow: View {
    let measurement: BandwidthMeasurementModel
    let unit: BandwidthUnit

    private var asBits: Bool { unit == .bits }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(measurement.deviceName)
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                    Text("\(Formatters.bytes(measurement.downloadBytes)) ↓ · \(Formatters.bytes(measurement.uploadBytes)) ↑ total")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 2) {
                    Text(Formatters.rate(UInt64(measurement.downloadBPS), asBits: asBits))
                        .font(.caption)
                        .foregroundStyle(.blue)
                    Text(Formatters.rate(UInt64(measurement.uploadBPS), asBits: asBits))
                        .font(.caption)
                        .foregroundStyle(.green)
                }
            }
            if !measurement.history.isEmpty {
                Chart(measurement.history) { point in
                    BarMark(
                        x: .value("Time", point.at, unit: .minute),
                        y: .value("Download", point.downloadBPS)
                    )
                    .foregroundStyle(Color.blue.gradient)
                }
                .frame(height: 44)
                .chartXAxis(.hidden)
                .chartYAxis(.hidden)
            }
            HStack {
                Text("Peak \(Formatters.rate(UInt64(measurement.peakDownloadBPS), asBits: asBits)) ↓ · \(Formatters.rate(UInt64(measurement.peakUploadBPS), asBits: asBits)) ↑")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Spacer()
            }
        }
        .padding(.vertical, 4)
    }
}