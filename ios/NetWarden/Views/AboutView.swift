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
                    label("Local network identity", "This device's IP addresses, subnet, hardware address, and Wi-Fi name.", .supported, "wifi")
                    label("Device discovery", "Reads the system neighbor (ARP) cache and sweeps the local subnet to find real hosts and MAC addresses.", .supported, "dot.radiowaves.left.and.right")
                    label("Device names & models", "Resolves the mDNS advertisements devices actually publish to show their real names, hostnames, models, and hardware IDs, with reverse DNS as a fallback.", .supported, "textformat.abc")
                    label("mDNS discovery", "Browse services advertised by devices on the network.", .supported, "antenna.radiowaves.left.and.right")
                    label("Traffic monitoring", "Live upload and download rates from this iPhone's real interface byte counters, plus peaks and usage history.", .supported, "chart.bar.xaxis")
                    label("Gateway integrity", "Watches the neighbor cache for a device claiming the gateway address and reports real conflicts.", .supported, "shield.lefthalf.filled")
                    label("IPv6 status", "Real learned prefixes and the default IPv6 route from the system routing table.", .supported, "globe.americas")
                    label("Device registry", "Starts from live scan results (real names, models, and MACs), supports import of desktop scan snapshots, and offers an optional synthetic sample.", .supported, "network")
                }

                Section("Experimental · cannot be enforced on iOS") {
                    label("Disconnect & restore", "Full control UI and control-audit logging; ARP/NDP redirection is recorded as not enforceable on iPhone.", .included, "hand.raised")
                    label("Bandwidth limits", "Per-device limit policies, unit handling, and audit entries; enforcement needs the privileged desktop forwarder.", .included, "speedometer")
                    label("Per-device traffic capture", "Rates for other devices are modelled; only this iPhone's own traffic can be measured without raw capture.", .included, "rectangle.stack.badge.person.crop")
                    label("Router Advertisement analysis", "Passive RA parsing and IPv6 router preferences need raw packets; iOS shows the routing table instead.", .included, "point.3.connected.trianglepath.dotted")
                }

                Section("Why enforcement is impossible") {
                    Text("iOS apps run in a sandbox with no raw-packet or privileged-low-level network access, so capture, ARP/NDP redirection, and shaping can never operate on this device. This build implements everything the sandbox does allow for real — discovery, throughput, and gateway integrity — and labels the rest plainly instead of faking it.")
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