# NetWarden

NetWarden is an open-source desktop app for seeing and managing the devices on
your local network. It gives you a live view of what is connected, helps you
recognize unfamiliar devices, and watches for unexpected changes to your
network gateway.

## What you can do

- Discover devices connected to your current network.
- See IP and MAC addresses, names, vendors, and estimated device types.
- Tell which devices are online now and review previously seen devices.
- Give devices memorable nicknames.
- Filter, sort, and select devices from one dashboard.
- Temporarily disconnect selected eligible devices and restore their access.
- Set temporary download and upload speed limits for eligible devices.
- Monitor live per-device upload/download rates, totals, peaks, and recent history.
- Monitor your gateway identity for suspicious changes.
- Passively discover IPv6 device addresses from validated Neighbor Discovery traffic.
- Review recent activity, errors, and control history in Diagnostics.
- Adjust scan timing, offline detection, history retention, and automatic
  startup.

## Download

Preview builds are available from [GitHub Releases](https://github.com/amdzy/NetWarden/releases):

- **Windows:** Download the Windows x64 ZIP, extract it, and run
  `NetWarden.exe`. [Npcap](https://npcap.com/) must be installed.
- **macOS:** Download the ZIP for Apple Silicon or Intel, extract it, and open
  `NetWarden.app`.
- **Linux:** Download the Linux x64 archive, extract it, and run `NetWarden`.
  GTK 3, WebKit2GTK 4.1, libpcap, PolicyKit, and `pkexec` are required.

Current preview builds are not signed or notarized. Windows may display an
unknown-publisher warning. macOS may initially block the app and require you to
approve it under **System Settings → Privacy & Security**.

## Getting started

1. Open NetWarden and choose the network interface you are currently using.
2. Start monitoring and approve the operating system's permission prompt.
3. Wait for the first scan to populate the Devices table.
4. Add nicknames to devices you recognize.
5. Open a device to disconnect it or apply a bandwidth limit when needed.
6. Review Gateway Security and Diagnostics if NetWarden reports a warning.

NetWarden asks for administrator permission only when packet access is needed.
The main desktop interface continues to run as your normal user account.

## Device identification

Names, vendors, and device types are best-effort hints. Many phones, tablets,
and computers use private or randomized MAC addresses, which can hide their
manufacturer. These devices may appear as **Private / Randomized** or
**Unknown** even when NetWarden is working correctly.

## Disconnect and restore

Disconnect controls are available only for eligible devices on your current
local network. NetWarden validates every control request and attempts to restore
affected devices when you restore them, stop monitoring, or close the app.

Network behavior differs between routers and devices, so treat this feature as
a local management tool rather than a permanent access-control system.

## Bandwidth limits

Open an eligible online device to set separate download and upload limits in
Mbps. Leave either direction at zero to keep it unlimited. Active limits appear
in the Devices table and remain in effect only while NetWarden is monitoring
the network; they are not saved or automatically reapplied after a restart.

Removing a limit restores the device's normal direct network path. Support depends on the local IPv4
network and may vary between routers, switches, and devices.

## Bandwidth monitor

Start monitoring an eligible IPv4 device from the Bandwidth view to route its
traffic through NetWarden without applying a speed limit. The view derives live
rates, session totals, peaks, and recent activity from aggregate forwarding
counters. Usage is compacted into persistent minute, hour, and day buckets for
hour/day/week/month views. Monitor-all rolls back newly installed routes if any
device fails, monitored IPv4 routes follow address changes, and forwarding
drops or sampling failures appear as health warnings. Monitoring routes remain
temporary and are restored when monitoring stops or NetWarden shuts down. IPv6
traffic classification, interception, accounting, monitoring, and limits use a
validated NDP redirection and restoration lifecycle.

## Privacy and responsible use

NetWarden works locally and is designed to inspect your current network. Use it
only on networks you own or are explicitly authorized to administer.

## Development

Requirements include Go, Node.js, the Wails v2 CLI, and the packet-capture and
desktop libraries for your operating system.

```sh
go test ./...
go vet ./...

cd cmd/netwarden-gui/frontend
npm ci
npm test -- --run
npm run build
npm run lint
```

Run the desktop app during development with:

```sh
go install github.com/wailsapp/wails/v2/cmd/wails@v2.13.0
make gui-dev
```

Use `make gui-build` to create a local packaged build. Version tags such as
`v2.0.1` trigger the GitHub Actions workflow, which builds unsigned preview
archives and prepares a draft GitHub Release.

## License

NetWarden is available under the [MIT License](LICENSE).
