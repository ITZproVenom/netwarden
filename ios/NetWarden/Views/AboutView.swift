import SwiftUI

struct AboutView: View {
    var body: some View {
        NavigationStack {
            List {
                Section {
                    HStack(spacing: 12) {
                        Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                            .font(.system(size: 34, weight: .medium))
                            .foregroundStyle(.tint)
                            .frame(width: 60, height: 60)
                            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                        VStack(alignment: .leading, spacing: 3) {
                            Text("NetWarden for iPhone")
                                .font(.headline)
                            Text("Standalone build · v1.0.0")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 4)
                }

                Section("Runs on iPhone") {
                    label("Local network identity", "This device's IP addresses and Wi-Fi name.", .supported, "wifi")
                    label("mDNS discovery", "Browse services advertised by devices on the network.", .supported, "antenna.radiowaves.left.and.right")
                    label("Device registry", "Import, browse, search, and nickname devices from a desktop scan snapshot.", .supported, "network")
                }

                Section("Experimental · cannot be enforced on iOS") {
                    label("ARP / NDP discovery", "Scan status and device census driven by the imported snapshot; live probing needs raw sockets iOS forbids.", .included, "point.3.connected.trianglepath.dotted")
                    label("Gateway security", "Gateway and IPv6 router identity analysis with active/restored conflict states; passive capture requires the desktop host.", .included, "shield")
                    label("Disconnect & restore", "Full control UI and control-audit logging; ARP/NDP redirection is recorded as not enforceable on iPhone.", .included, "hand.raised")
                    label("Bandwidth limits", "Per-device limit policies, unit handling, and audit entries; enforcement needs the privileged desktop forwarder.", .included, "speedometer")
                    label("Traffic monitoring", "Live rates, totals, peaks, health, and usage-history buckets in NetWarden's exact shapes; monitoring uses userspace forwarding.", .included, "chart.bar.xaxis")
                }

                Section("Why enforcement is impossible") {
                    Text("iOS apps run in a sandbox with no raw-packet or privileged-low-level network access, so capture, control, and shaping can never operate on this device. This build wires every desktop feature surface into the app, tags the non-enforceable ones Experimental, and labels exactly what cannot be enforced, so the unmodified NetWarden remains on macOS and the desktop app.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .background(AppBackground())
            .scrollContentBackground(.hidden)
            .navigationTitle("Feature scope")
        }
    }

    private enum Support: String {
        case supported = "checkmark.circle.fill"
        case included = "magnifyingglass.circle.fill"
        case unavailable = "xmark.circle"
    }

    private func label(_ title: String, _ detail: String, _ support: Support, _ icon: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: support.rawValue)
                .font(.title3)
                .foregroundStyle(color(for: support))
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(.tertiary)
                .frame(width: 36)
        }
        .padding(.vertical, 4)
    }

    private func color(for support: Support) -> Color {
        switch support {
        case .supported: return .green
        case .included: return .accentColor
        case .unavailable: return .secondary
        }
    }
}