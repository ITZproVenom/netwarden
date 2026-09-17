# NetWarden Agent Guide

This file is the durable handoff for coding agents working in this repository. Read it before changing code. Keep it concise and update it when architecture or project decisions materially change.

## Product and constraints

NetWarden is a Go/Wails desktop application for local-network discovery, device identity, gateway-security monitoring, temporary device controls, bandwidth limits, and per-device traffic monitoring.

- Packet capture and narrowly validated packet transmission run through a privileged helper. Do not move packet payloads or arbitrary-send capability into the unprivileged GUI process.
- Network controls are temporary. Existing IPv4 paths restore legitimate ARP state when controls stop or the application shuts down.
- Preserve user changes in a dirty worktree. Do not reset or rewrite unrelated files.
- Monitoring/limiting uses ARP redirection and userspace forwarding. This can substantially reduce maximum throughput on fast links. This behavior is accepted for now; do not pursue throughput work unless explicitly requested.
- Automatic restoration triggered by scheduler overload was deliberately deferred. Normal stop/shutdown restoration still applies.

## Repository map

- `cmd/netwarden-gui/`: Wails application boundary, DTOs, application logging, and frontend bindings.
- `cmd/netwarden-gui/frontend/src/features/`: React feature views and queries.
- `internal/app/`: runtime composition, lifecycle, bandwidth service, and high-level orchestration.
- `internal/core/`: capture consumption and device-observation service.
- `internal/capture/`: capture interfaces, privileged helper protocol/client, and pcap/Npcap adapter.
- `internal/control/`: IPv4 device-control lifecycle.
- `internal/device/`: device registry and multi-address identity.
- `internal/discovery/`: ARP discovery plus IPv6 router/prefix tracking.
- `internal/packet/`: validated ARP and ICMPv6 Neighbor Discovery parsing/marshalling.
- `internal/shaping/`: policies, token-bucket limiter, bounded forwarding queues, per-flow scheduler, and traffic counters.
- `internal/traffic/`: live rates, peaks, and compact usage history.
- `internal/history/`: persisted application/device/history snapshots.
- `internal/config/`: settings storage and defaults.
- `internal/applog/`: bounded rotating JSONL application logs.
- `internal/defense/` and `internal/controlaudit/`: gateway protection events and control audit history.
- `ios/`: native SwiftUI iPhone standalone build of the full NetWarden feature set (XcodeGen spec in `project.yml`, committed Xcode project plus generated sources, unsigned-IPA CI in `.github/workflows/ios.yml`). `LocalNetworkScanner` implements the real on-device capability the iOS sandbox allows — ARP-cache device discovery, a UDP subnet sweep, interface byte counters, default-route/IPv6-prefix reads, and ARP-based gateway conflict detection — while `BonjourResolver` maps real mDNS instance names, hostnames, model identifiers, and TXT MACs onto those hosts, so devices are listed by their actual names rather than a vendor guess. Capabilities iOS cannot enforce (ARP/NDP redirection, per-device capture, shaping, RA analysis) are tagged **Experimental** and labeled plainly in the UI and control audit. It must not pull desktop capture/control code; iOS has no raw-packet access. See `ios/README.md`.

## Bandwidth architecture

The active forwarding path is:

```text
capture/classification
        -> bounded upload/download admission (4096 packets and 6 MiB each)
        -> per-device/per-direction flow queues
        -> eligibility and weighted-fair scheduler
        -> single serialized packet transmitter
```

Important files:

- `internal/shaping/forwarder.go`: classification, admission bounds, forwarding health, IPv4/IPv6 Ethernet rewrites, accounting.
- `internal/shaping/scheduler.go`: per-device/per-direction flow ownership, round-robin fairness, monitoring priority, and serialized transmission.
- `internal/shaping/limiter.go` and `manager.go`: token reservations and non-blocking eligibility timestamps.
- `internal/capture/helper/bandwidth.go`: privileged bandwidth session and IPv4 ARP redirection/restoration.
- `internal/capture/helper/protocol.go`: narrow helper command validation and serialized driver access.
- `internal/app/bandwidth.go`: monitored/limited target state and reconciliation.
- `cmd/netwarden-gui/bandwidth.go`: GUI DTOs and health-transition logging.

Scheduler policy currently gives unrestricted monitoring traffic an eight-packet priority burst, then serves eligible limited traffic so it cannot starve. Service is round-robin within each class. Queue reservations remain charged until transmission/cancellation, including while packets live in flow queues.

Bandwidth health exposes direction, operating mode, current/peak packet and byte pressure, recent deltas, and per-device drops. The GUI logs transitions as `bandwidth monitor health degraded` and `bandwidth monitor health recovered` without logging every poll.

Application logs on macOS are normally at:

```text
~/Library/Application Support/netwarden/logs/netwarden.jsonl
```

## IPv6 status

Implemented:

- Validated passive ICMPv6 Neighbor Discovery parsing and observation.
- Multiple IPv4, link-local IPv6, and global IPv6 addresses grouped under device MAC identity.
- Secondary IPv6 address expiration.
- Router Advertisement parsing, default-router selection, prefix/lifetime tracking, and persisted trust/conflict state.
- IPv6 network/status UI.
- IPv6 frame classification, Ethernet rewriting, scheduling, and traffic accounting once traffic reaches the forwarder.
- NDP redirection, refresh, and corrective restoration for verified router and device identities.
- Narrow privileged-helper IPv6 control: the GUI supplies identities and policies, while the helper exclusively marshals validated Neighbor Advertisements.
- Device-level dual-stack monitoring and limits across IPv4 plus all known IPv6 addresses, with one per-MAC accounting identity.
- IPv6-only and dual-stack monitoring/limits, including reconciliation when privacy addresses are learned or expire.
- Bounded active IPv6 discovery using known on-link addresses and EUI-64 candidates derived from learned `/64` prefixes. Probes use solicited-node multicast and never enumerate a `/64`.
- IPv6-only and dual-stack disconnect/isolation using helper-owned NDP redirection, packet dropping, refresh for continuous controls, privacy-address reconciliation, and corrective restoration.

IPv6 isolation blocks traffic routed through the verified default router. Direct
peer-to-peer link-local traffic is not intercepted by the current host-routing
design and is outside the ordinary disconnect control's guarantee.

Lower-priority IPv6 work includes a reusable extension-header parser (the NDP parser intentionally rejects extension headers), multi-router/privacy-address live tests, and SEND-aware behavior. Do not implement automatic overload restoration as part of this roadmap unless newly requested.

## Validation

Run focused tests while iterating, then the complete checks relevant to the change:

```sh
env GOCACHE=/tmp/netwarden-go-cache go test ./...
env GOCACHE=/tmp/netwarden-go-race-cache go test -race ./internal/shaping

cd cmd/netwarden-gui/frontend
npm run build
npm run lint
```

The host Go cache may be inaccessible in sandboxed sessions, so use the `/tmp` cache paths above. libpcap may emit a harmless duplicate-library linker warning on macOS.

Before handoff, also run:

```sh
git diff --check
git diff --cached --check
git status --short
```

Do not format the entire frontend solely to satisfy Prettier: some existing feature files intentionally have compact formatting, and whole-file formatting creates noisy unrelated diffs. Format only touched regions/files when appropriate.

## Testing expectations

- Packet parsing must include malformed/truncated/checksum/identity rejection tests.
- Forwarding changes must cover upload/download, IPv4/IPv6, cancellation, queue saturation, accounting, and send errors.
- Scheduler changes must cover per-device fairness, monitoring priority, non-starvation of limited flows, head-of-line isolation, single-transmitter behavior, admission bounds after flow ingestion, removed-flow cleanup, repeated runs, and the race detector.
- Privileged-helper changes require both allow and deny tests; keep the protocol incapable of arbitrary frame injection.
- Lifecycle changes must test rollback and restoration paths, not only successful activation.
