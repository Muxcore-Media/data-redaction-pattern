# Changelog

## [0.1.5] — 2026-08-10

### Fixed

- Self-hosted CI (`runs-on: self-hosted`; `go test` without `-race` for laptop runners)

### Changed

- `muxcore.json` / `Info()` align `minCoreVersion` and contract pin to **0.5.0** (matches `go.mod` core **v0.5.8**)

## [0.1.4] — 2026-08-10

### Added

- Advertise `settings` capability so admin-ui discovers SettingsProvider without ListAll probing.

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0/).

## [Unreleased]

### Changed

- Inbound gRPC listener now uses TLS by default on `127.0.0.1:9655` (umbrella#55).
- Auto-generate dev certificates under `~/.muxcore/tls/data-redaction-pattern` when no cert paths are configured.
- Plaintext gRPC available only when `MUXCORE_INSECURE_DISABLE_TLS` or `MUXCORE_GRPC_INSECURE` is set.

## [0.1.3] — 2026-08-10

### Added

- `RegisterSettings` / `SettingsUpdater` for live `extra_keys` (`REDACTION_EXTRA_KEYS`)
- Pin `core` / contracts / `sdk/go/module` to **v0.5.8**

## [0.1.2] — 2026-08-10

### Fixed
- Sync Info()/muxcore.json version to **0.1.2**.

## [0.1.1] — 2026-08-09

### Added

- CHANGELOG and COMPATIBILITY documentation.

## [0.1.0] — 2026-08-09

### Added

- PII redaction sidecar (`data.redaction`): `field:`, `path:`, and `/regex/` rules plus default sensitive keys.
- `Redact` / `SupportedRules` gRPC; listen default `:9655` (`REDACTION_GRPC_ADDR`).
