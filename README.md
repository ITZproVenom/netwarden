# NetWarden

NetWarden is an open-source network visibility and management tool. The active
implementation is being rebuilt in Go around a testable, platform-independent
core. The previous C# implementation is preserved in [`old_app`](old_app/).

## Current status

The new implementation currently provides:

- IPv4 subnet enumeration that respects the configured prefix.
- Ethernet/ARP packet encoding and decoding.
- A concurrency-safe registry of observed devices.
- Cancellable foreground and periodic discovery services.
- Liveness tracking based on elapsed duration.
- Interfaces that keep privileged packet capture outside the application core.
- A libpcap/Npcap adapter for interface enumeration, filtered capture, and
  Ethernet frame transmission.
- Diagnostic commands for interface listing, ARP scanning, and explicit ARP
  address resolution.
- Versioned, atomic JSON configuration with saved interface selection and
  device nicknames.
- Embedded OUI vendor resolution for observed MAC addresses.
- An explicitly enabled, concurrency-safe device-control state machine with
  strict local-target validation and corrective restoration on explicit
  restore, send failure, and shutdown.
- A validated network context built from the selected adapter and operating
  system default IPv4 route.
- A one-shot application runtime that owns discovery, capture, device roles,
  passive integrity monitoring, cancellation, and ordered shutdown.
- Passive, debounced reporting when an observed gateway identity conflicts
  with the startup baseline. Passive monitoring never transmits corrections.

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
go run ./cmd/netwarden nickname set 00:11:22:33:44:55 "Living Room TV"
sudo go run ./cmd/netwarden scan --interface en0 --duration 5s
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

NetWarden should only be used on networks you own or are explicitly authorized
to administer.

## License

NetWarden is licensed under the [MIT License](LICENSE).
