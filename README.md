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
- Monitor your gateway identity for suspicious changes.
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
5. Review Gateway Security and Diagnostics if NetWarden reports a warning.

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
