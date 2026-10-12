# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

Phases 0 (repo scaffolding) and 1 (proto API) are done; everything else is design agreed with the user before implementation. `ROADMAP.md` is the step-by-step plan from empty repo to 1.0, with numbered steps (e.g. `7.10`): follow its order, tick `[x]` when a step is done, and reference step numbers in commits. 

## Commands

- `just build` builds `berylliumd` and `beryl` into `bin/` (version is injected via ldflags into `internal/version`)
- `just test` runs `go test -race ./...`; for a single test, `go test -run TestName ./internal/<pkg>`
- `just lint` runs golangci-lint (v2 config in `.golangci.yml`; `gen/` is excluded) and checks gofmt
- `just gen` formats protos and regenerates `gen/go` (committed; CI fails if it is stale). `just breaking` checks proto changes against `main`
- buf, protoc-gen-go and protoc-gen-go-grpc are tool deps in the separate `tools/go.mod` module and run via `go tool -modfile=tools/go.mod <tool>`. Don't install them globally, and don't add tool deps to the root `go.mod`
- `just fetch-cores` / `gui-dev` are placeholders until ROADMAP 5.2 / 9.1

Module path: `github.com/vvaeli/beryllium`. License: GPL-3.0.

Planned layout: `proto/beryllium/v1/` (API), `gen/go/`, `cmd/berylliumd/` (daemon), `cmd/beryl/` (CLI+TUI), `internal/`, `gui/` (Tauri), `cores/`, `packaging/`.

## Project

Beryllium is a cross-platform desktop proxy/VPN client for Arch Linux, macOS and Windows. It imports a subscription link that can contain any protocol (VLESS+Reality, XHTTP, Hysteria2, TUIC, Trojan, SS, WireGuard, AmneziaWG, ...). The main motivation is reliability: the previous client (Incy) intermittently loses the tunnel after macOS sleep. Surviving sleep/wake and network changes is a core requirement, not a nice-to-have.

## Planned architecture

- **Daemon (Go)**: privileged service: systemd on Linux, launchd daemon on macOS (no Network Extension, because there is no Apple Developer account), Windows Service. It owns the tunnel, subscriptions, core management and the watchdog.
- **Frontends**: three unprivileged clients of the same daemon API. They talk to the daemon over gRPC on a unix socket (Linux/macOS) or a named pipe (Windows). The VPN keeps running if a frontend exits.
  - **GUI (Rust, Tauri v2)**: tray app.
  - **CLI + TUI (Go)**: a single binary that reuses the generated gRPC client. Subcommands make up the CLI, and `tui` (or no arguments) starts the TUI (bubbletea). Built as a separate artifact so it can be used without the GUI, e.g. on a headless Arch box or over SSH.
  - All business logic lives in the daemon. Frontends only call the API, so all three behave the same.
- **Modes**: both TUN and system proxy, switchable at runtime.
- **Subscriptions**: nothing is bundled or hardcoded. The user adds their subscription URL from any frontend (GUI, TUI or CLI) via an `AddSubscription`-style API call. The daemon fetches, parses and stores it, refreshes it periodically and stores it with owner-only permissions.
- **IPC access control**: the daemon runs privileged, so the socket/pipe must be restricted to the owning user or a dedicated group. Otherwise any local user could change routing or read subscriptions.

### Multi-core design

- Cores run as **separate subprocesses**, not embedded libraries. sing-box and Xray depend on conflicting versions of shared modules (quic-go, utls), and process isolation means a core crash cannot take down the daemon.
- Cores sit behind a common `Core` interface (Start/Stop/HealthCheck/Stats), with one config translator per core.
- **sing-box always owns TUN.** Other cores (Xray, mihomo) expose a local SOCKS inbound, and sing-box routes TUN traffic to it. Sleep/DNS/route handling therefore lives in one place.
- Core selection: first a capability matrix (e.g. XHTTP → Xray only; Hysteria2/TUIC → sing-box), then measured latency/stability when several cores qualify. The user can override the choice manually.
- Core set: sing-box (primary), Xray (XHTTP, newest VLESS/Reality features), mihomo (AmneziaWG, via `amnezia-wg-option`). Don't add cores that offer nothing beyond these.

### Sleep/wake and network-change recovery (macOS-critical)

1. On `kIOMessageSystemWillSleep`, close outbound connections.
2. On `kIOMessageSystemHasPoweredOn`, wait until the network is actually ready (default route, active interface, DNS resolves). Don't reconnect immediately, because that race is the suspected cause of the intermittent drops.
3. Then reset core connections, re-detect the default interface, flush DNS (`dscacheutil -flushcache` + HUP `mDNSResponder`) and run a health check.
4. If the check fails, restart the core. If that also fails, fall back to another server or core.
5. A periodic URL-test watchdog (~20–30s; recover after 2–3 consecutive failures) runs independently of events, to catch DarkWake/Power Nap and missed notifications.

## Conventions

- The subscription URL is a secret: never commit it, log it in full, or paste it into tooling output.

## API (proto)

`proto/beryllium/v1/*.proto` is the single contract for the daemon and all three frontends. buf STANDARD lint applies: every RPC has its own `<Rpc>Request`/`<Rpc>Response`, and enum values are prefixed with the enum name and start with `_UNSPECIFIED`. Errors are gRPC status codes with `ErrorDetail` (an `ErrorReason`) in the details. Credentials and full subscription URLs never cross the API, except through `GetShareLink` (for copy/QR), which frontends call only on explicit user action and must never log or cache. `Server` is a public view, and `Subscription` has only `url_masked`.

## Packaging

Linux ships only as native packages (Arch `.pkg.tar.zst` + AUR, `.deb`, `.rpm` via nfpm), never AppImage. Each package installs the daemon, systemd unit, sysusers group, cores and GUI (ROADMAP 10.9).
