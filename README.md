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
- Diagnostic commands for interface listing, ARP scanning, and explicit ARP
  address resolution.
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
  and gateway-conflict history.
- Periodic default-route checks that stop the one-shot runtime cleanly when the
  active network changes, allowing the application layer to rebuild it.

The interactive TUI and GUI will be added after the capture and discovery path
has been exercised across supported operating systems.

Active device control is intentionally not exposed by the diagnostic CLI yet.
Its core is packet-tested, defaults to disabled, rejects the local host,
gateway, off-subnet and broadcast targets, and never persists active isolation
state across application restarts.

## Diagnostic CLI

```sh
go run ./cmd/netwarden interfaces
go run ./cmd/netwarden route
go run ./cmd/netwarden config set-interface en0
go run ./cmd/netwarden config set-gateway-mac 00:11:22:33:44:55
go run ./cmd/netwarden nickname set 00:11:22:33:44:55 "Living Room TV"
sudo go run ./cmd/netwarden scan --interface en0 --duration 5s
sudo go run ./cmd/netwarden monitor --interface en0 --interval 10s
sudo go run ./cmd/netwarden resolve --interface en0 --gateway 192.168.1.1
```

Configuration is stored beneath the operating system's user configuration
directory. Set `NETWARDEN_CONFIG` to use an explicit file, which is useful for
development and for the future privileged-helper boundary.

Linux and macOS builds require libpcap development files; Windows builds use
Npcap. Capture and transmission generally require elevated privileges.

## Development

```sh
go test ./...
go vet ./...
```

CI runs tests, vet, and builds on Linux, macOS, and Windows, with an additional
Linux race-detector and formatting job.

NetWarden should only be used on networks you own or are explicitly authorized
to administer.

## License

NetWarden is licensed under the [MIT License](LICENSE).
