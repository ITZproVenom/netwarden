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
            SecurityView()
                .tabItem {
                    Label("Security", systemImage: "shield")
                }
            BandwidthView()
                .tabItem {
                    Label("Bandwidth", systemImage: "speedometer")
                }
            ActivityView()
                .tabItem {
                    Label("Activity", systemImage: "list.bullet.rectangle")
                }
        }
    }
}