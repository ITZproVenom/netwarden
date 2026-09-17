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
                            Text("Companion to the desktop app · v1.0.0")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 4)
                }

                Section("Runs on iPhone") {
                    label("Local network identity", "This device's IP addresses and Wi-Fi name.", true, "wifi")
                    label("mDNS discovery", "Browse services advertised by devices on the network.", true, "antenna.radiowaves.left.and.right")
                    label("Device registry", "Import, browse, search, and nickname devices from a desktop scan snapshot.", true, "network")
                }

                Section("Desktop-only — raw packet access required") {
                    label("ARP / NDP discovery", "Highlighting every device requires privileged raw sockets, which iOS forbids.", false, "point.3.connected.trianglepath.dotted")
                    label("Gateway security", "Detecting a changed gateway needs passive capture of gateway traffic.", false, "shield")
                    label("Disconnect & restore", "Bouncing devices needs ARP/NDP redirection, not available to iOS apps.", false, "hand.raised")
                    label("Bandwidth limits & monitoring", "Shaping traffic needs userspace packet forwarding.", false, "speedometer")
                }

                Section("Why the gap") {
                    Text("iOS apps run in a sandbox with no raw-packet or privileged-low-level network access. NetWarden's capture, control, and monitoring pipeline depends on exactly that access, so those features cannot run on iPhone. The dedicated desktop and Mac apps remain the full NetWarden.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .background(AppBackground())
            .scrollContentBackground(.hidden)
            .navigationTitle("Feature scope")
        }
    }

    private func label(_ title: String, _ detail: String, _ supported: Bool, _ icon: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: supported ? "checkmark.circle.fill" : "xmark.circle")
                .font(.title3)
                .foregroundStyle(supported ? Color.green : Color.secondary)
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
}