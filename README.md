# NetWarden

NetWarden is an open-source network visibility and management tool. The active
implementation is being rebuilt in Go around a testable, platform-independent
core. The previous C# implementation is preserved in [`old_app`](old_app/).

## Current status

The new implementation currently provides:

- IPv4 subnet enumeration that respects the configured prefix.
- Ethernet/ARP packet encoding and decoding.
- A concurrency-safe registry with MAC/IP identity indexes, conflict events,
  online/offline transitions, address moves, and stale-record retention.
- Cancellable foreground and periodic discovery services.
- Liveness tracking based on elapsed duration.
- Interfaces that keep privileged packet capture outside the application core.
- A libpcap/Npcap adapter for interface enumeration, filtered capture, and
  Ethernet frame transmission.
- Versioned, atomic JSON configuration with saved interface selection, device
  nicknames, and an optional pinned gateway MAC baseline.
- Embedded OUI vendor resolution for observed MAC addresses.
- Non-blocking reverse-DNS hostname resolution with deduplicated lookups,
  bounded timeouts, caching, and live metadata refresh events.
- An explicitly enabled, concurrency-safe device-control state machine with
  strict local-target validation and corrective restoration on explicit
  restore, send failure, and shutdown.
- A validated network context built from the selected adapter and operating
  system default IPv4 route.
- A one-shot application runtime that owns discovery, capture, device roles,
  passive integrity monitoring, cancellation, and ordered shutdown.
- Passive, debounced reporting when an observed gateway identity conflicts
  with a learned or pinned baseline, including conflict history and restoration
  events. Passive monitoring never transmits corrections.
- Cross-process configuration locking on Unix and Windows.
- Live nickname updates that persist first and then refresh existing device
  snapshots without restarting capture.
- A unified typed runtime event stream, lifecycle/scan events, event-drop
  accounting, and stage-aware native error categories.
- Version-controlled recorded-packet fixtures for capture-path regression tests.
- Durable device and gateway-conflict history stored separately from settings;
  restored peers remain offline until observed on the current run.
- Runtime APIs for manual scans, periodic-scan pause/resume, status snapshots,
  and gateway-conflict history used by the desktop GUI.
- A restart supervisor that rebuilds capture and discovery after interface or
  default-route changes while keeping one stable event stream for frontends.
- Queryable and pruneable history in the desktop GUI, with a default 90-day
  retention window.
- An optional cross-platform subprocess privilege boundary. The helper only
  permits filtered capture and strictly validated local ARP discovery requests.
- Periodic default-route checks that stop the one-shot runtime cleanly when the
  active network changes, allowing the application layer to rebuild it.

The Wails v2 desktop GUI now has an initial network dashboard backed by the Go
runtime. It supports interface selection, live device updates, manual and
periodic discovery, nickname editing, history management, and diagnostics.
Packet capture requires platform-specific permissions. On macOS the GUI
requests administrator approval for its restricted capture-helper subprocess
while the desktop app continues to run as the signed-in user. Other platforms
currently retain the direct-capture behavior.

Configuration is stored beneath the operating system's user configuration
directory. Set `NETWARDEN_CONFIG` to use an explicit file during development.

Linux and macOS builds require libpcap development files; Windows builds use
Npcap. Capture and transmission generally require elevated privileges.

The GUI's elevated capture-helper subprocess cannot send arbitrary frames; it
validates the interface identity, subnet, Ethernet destination, ARP operation,
and target before transmission.

## Development

```sh
go test ./...
go vet ./...
```

To run the desktop GUI, install the Wails v2 CLI and start its development
server:

```sh
go install github.com/wailsapp/wails/v2/cmd/wails@latest
make gui-dev
```

Use `make gui-build` to create a packaged desktop build.

CI runs tests, vet, and builds on Linux, macOS, and Windows, with an additional
Linux race-detector and formatting job.

NetWarden should only be used on networks you own or are explicitly authorized
to administer.

## License

NetWarden is licensed under the [MIT License](LICENSE).
