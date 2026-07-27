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

Persistence, the interactive TUI, and the GUI will be added after the capture
and discovery path has been exercised across supported operating systems.

## Diagnostic CLI

```sh
go run ./cmd/netwarden interfaces
sudo go run ./cmd/netwarden scan --interface en0 --duration 5s
sudo go run ./cmd/netwarden resolve --interface en0 --gateway 192.168.1.1
```

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
