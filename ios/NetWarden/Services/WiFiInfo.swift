import Foundation
import NetworkExtension

struct WiFiDetails {
    let ssid: String?
    let bssid: String?
}

enum WiFiInfo {
    static func fetchCurrent(_ completion: @escaping (WiFiDetails?) -> Void) {
        NEHotspotNetwork.fetchCurrent { network in
            if let network {
                completion(WiFiDetails(
                    ssid: network.ssid.isEmpty ? nil : network.ssid,
                    bssid: network.bssid.isEmpty ? nil : network.bssid
                ))
            } else {
                completion(nil)
            }
        }
    }
}