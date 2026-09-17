import SwiftUI

@main
struct NetWardenApp: App {
    @State private var deviceStore = DeviceStore()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(deviceStore)
        }
    }
}