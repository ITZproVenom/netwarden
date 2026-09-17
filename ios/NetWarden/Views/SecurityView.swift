import SwiftUI

struct SecurityView: View {
    @Environment(StandaloneRuntime.self) private var runtime

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    platformNote
                    gatewaySecurityCard
                    ipv6IntegrityCard
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
            }
            .background(AppBackground())
            .navigationTitle("Gateway security")
        }
    }

    private var platformNote: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "lock.iphone")
                .font(.title3)
                .foregroundStyle(.tint)
            Text("Gateway identity is checked against the kernel ARP cache, which iOS exposes read-only, so real impersonation conflicts are reported here. Router Advertisement analysis and IPv6 redirection need raw packets and stay on the desktop app.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(16)
        .glassPanel(cornerRadius: 18)
    }

    private var gatewaySecurityCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            PanelHeader(
                systemImage: "shield",
                title: "Gateway security",
                subtitle: "Detect devices attempting to impersonate your router",
                tag: "Experimental"
            )
            HStack(spacing: 8) {
                Label(
                    runtime.gatewayConflicts.isEmpty || runtime.activeConflictCount == 0
                        ? "No active warnings"
                        : "\(runtime.activeConflictCount) active warning\(runtime.activeConflictCount == 1 ? "" : "s")",
                    systemImage: runtime.activeConflictCount == 0 ? "checkmark.shield.fill" : "exclamationmark.triangle.fill"
                )
                .font(.footnote)
                .foregroundStyle(runtime.activeConflictCount == 0 ? Color.green : Color.orange)
                Spacer()
            }
            if runtime.gatewayConflicts.isEmpty {
                Text("No gateway conflicts observed")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(runtime.gatewayConflicts) { conflict in
                    gatewayConflictRow(conflict)
                }
            }
            Divider()
            Button {
                runtime.toggleDemoConflict()
            } label: {
                Label(runtime.activeConflictCount == 0 ? "Demonstrate conflict" : "Resolve demonstration", systemImage: "arrow.triangle.2.circlepath")
            }
            .font(.footnote)
        }
        .padding(18)
        .glassPanel()
    }

    private func gatewayConflictRow(_ conflict: GatewayConflict) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("Unexpected gateway identity detected", systemImage: conflict.active ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                    .font(.subheadline)
                    .foregroundStyle(conflict.active ? Color.orange : Color.green)
                Spacer()
                Badge(text: conflict.active ? "Active" : "Restored", color: conflict.active ? .orange : .green)
            }
            InfoRow(label: "Unexpected gateway MAC", value: conflict.claimedMAC)
            InfoRow(label: "Gateway", value: "\(conflict.gatewayIP) · \(conflict.expectedMAC)")
            InfoRow(label: "First seen", value: Formatters.shortDateTime(conflict.firstSeen))
            InfoRow(label: "Last seen", value: Formatters.shortDateTime(conflict.lastSeen))
            InfoRow(label: "Observations", value: "\(conflict.count)")
        }
        .padding(12)
        .glassPanel(cornerRadius: 16)
    }

    private var ipv6IntegrityCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            PanelHeader(
                systemImage: "point.3.connected.trianglepath.dotted",
                title: "IPv6 router integrity",
                subtitle: "Default route, learned prefixes, and identity claims",
                tag: "Experimental"
            )
            if let routerIP = runtime.ipv6Network.defaultRouterIP {
                InfoRow(label: "Default router", value: "\(routerIP) · \(runtime.ipv6Network.defaultRouterMAC ?? "—")")
            }
            if runtime.ipv6Network.routers.isEmpty {
                Text("No routers learned")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(runtime.ipv6Network.routers) { router in
                    ipv6RouterRow(router)
                }
            }
            if !runtime.ipv6Network.conflicts.isEmpty {
                Divider()
                Text("IPv6 identity history")
                    .font(.headline)
                ForEach(runtime.ipv6Network.conflicts) { conflict in
                    HStack(spacing: 10) {
                        Image(systemName: conflict.active ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                            .foregroundStyle(conflict.active ? Color.orange : Color.green)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(conflict.routerIP)")
                                .font(.subheadline)
                                .monospaced()
                            Text("\(conflict.claimedMAC) claimed; trusted \(conflict.expectedMAC)")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Badge(text: conflict.active ? "Active" : "Restored", color: conflict.active ? .orange : .green)
                    }
                }
            }
            if !runtime.ipv6Network.trustedIdentities.isEmpty {
                Divider()
                Text("Learned router identities")
                    .font(.headline)
                ForEach(runtime.ipv6Network.trustedIdentities, id: \.self) { identity in
                    InfoRow(label: identity.routerIP, value: identity.mac)
                }
            }
        }
        .padding(18)
        .glassPanel()
    }

    private func ipv6RouterRow(_ router: IPv6RouterModel) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(router.ip)
                    .font(.subheadline)
                    .monospaced()
                Spacer()
                Badge(text: router.preferenceLabel, color: .accentColor)
            }
            InfoRow(label: "Identity", value: router.mac ?? "unknown")
            if let expiresAt = router.expiresAt {
                InfoRow(label: "Expires", value: Formatters.shortTime(expiresAt))
            }
            if !router.prefixes.isEmpty {
                Text("Advertised prefixes")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.top, 2)
                FlowLayout(spacing: 6) {
                    ForEach(router.prefixes, id: \.self) { prefix in
                        Text(prefix.prefix + (prefix.onLink ? " · on-link" : " · off-link"))
                            .font(.caption2)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 4)
                            .background(.thinMaterial, in: Capsule())
                    }
                }
            }
        }
        .padding(12)
        .glassPanel(cornerRadius: 16)
    }
}

struct Badge: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(color.opacity(0.16), in: Capsule())
            .foregroundStyle(color)
    }
}

/// Minimal left-to-right wrapping container for prefix chips.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var width: CGFloat = 0
        var height: CGFloat = 0
        var rowWidth: CGFloat = 0
        var rowHeight: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if rowWidth + size.width > maxWidth, rowWidth > 0 {
                width = max(width, rowWidth)
                height += rowHeight + spacing
                rowWidth = size.width
                rowHeight = size.height
            } else {
                rowWidth += (rowWidth > 0 ? spacing : 0) + size.width
                rowHeight = max(rowHeight, size.height)
            }
        }
        width = max(width, rowWidth)
        height += rowHeight
        return CGSize(width: width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX
        var y = bounds.minY
        var rowHeight: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x + size.width > bounds.maxX, x > bounds.minX {
                x = bounds.minX
                y += rowHeight + spacing
                rowHeight = 0
            }
            subview.place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}