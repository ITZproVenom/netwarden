import SwiftUI

@main
struct NetWardenApp: App {
    @State private var deviceStore: DeviceStore
    @State private var runtime: StandaloneRuntime

    init() {
        let store = DeviceStore()
        _deviceStore = State(initialValue: store)
        _runtime = State(initialValue: StandaloneRuntime(store: store))
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(deviceStore)
                .environment(runtime)
        }
    }
}