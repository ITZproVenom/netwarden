import SwiftUI

struct RootView: View {
    var body: some View {
        TabView {
            NetworkView()
                .tabItem {
                    Label("Network", systemImage: "wifi")
                }
            DevicesView()
                .tabItem {
                    Label("Devices", systemImage: "network")
                }
            DiscoverView()
                .tabItem {
                    Label("Discover", systemImage: "antenna.radiowaves.left.and.right")
                }
            AboutView()
                .tabItem {
                    Label("Scope", systemImage: "scope")
                }
        }
    }
}