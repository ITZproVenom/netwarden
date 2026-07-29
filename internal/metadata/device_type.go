package metadata

import (
	"strings"

	"github.com/amdzy/NetWarden/internal/device"
)

// identifyType uses only strong hostname and vendor signals. Ambiguous vendors
// (for example Apple, Samsung, and Google) intentionally remain unknown unless
// the hostname provides a more specific clue.
func identifyType(name, vendor string) device.Type {
	name = strings.ToLower(name)
	vendor = strings.ToLower(vendor)

	for _, rule := range typeRules {
		for _, signal := range rule.names {
			if strings.Contains(name, signal) {
				return rule.deviceType
			}
		}
	}
	for _, rule := range typeRules {
		for _, signal := range rule.vendors {
			if strings.Contains(vendor, signal) {
				return rule.deviceType
			}
		}
	}
	return device.TypeUnknown
}

var typeRules = []struct {
	deviceType device.Type
	names      []string
	vendors    []string
}{
	{device.TypePrinter, []string{"printer", "laserjet", "officejet", "deskjet", "photosmart"}, []string{"hewlett packard", "brother industries", "lexmark", "seiko epson", "canon inc."}},
	{device.TypePhone, []string{"iphone", "android", "galaxy-s", "pixel-", "oneplus"}, nil},
	{device.TypeTablet, []string{"ipad", "tablet", "galaxy-tab", "kindle"}, nil},
	{device.TypeTV, []string{"smart-tv", "smarttv", "appletv", "apple-tv", "chromecast", "firetv", "fire-tv", "roku"}, []string{"roku", "vizio", "hisense", "tcl king"}},
	{device.TypeGameConsole, []string{"xbox", "playstation", "ps4", "ps5", "nintendo", "switch"}, []string{"nintendo co.", "sony interactive entertainment"}},
	{device.TypeSpeaker, []string{"homepod", "sonos", "echo-", "google-home", "nest-audio"}, []string{"sonos"}},
	{device.TypeCamera, []string{"camera", "cam-", "doorbell", "ring-", "arlo"}, []string{"arlo technologies", "ring llc"}},
	{device.TypeNetwork, []string{"router", "gateway", "access-point", "accesspoint", "unifi", "deco-"}, []string{"ubiquiti", "netgear", "tp-link", "mikrotik", "aruba networks"}},
	{device.TypeComputer, []string{"macbook", "imac", "desktop", "laptop", "workstation", "raspberrypi", "raspberry-pi"}, []string{"raspberry pi"}},
	{device.TypeSmartHome, []string{"thermostat", "smartplug", "smart-plug", "lightbulb", "light-bulb"}, []string{"espressif", "tuya", "shelly"}},
}
