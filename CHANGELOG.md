# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0/).

## [Unreleased]

## [0.1.1] — 2026-08-09

### Added

- CHANGELOG and COMPATIBILITY documentation.

## [0.1.0] — 2026-08-09

### Added

- PII redaction sidecar (`data.redaction`): `field:`, `path:`, and `/regex/` rules plus default sensitive keys.
- `Redact` / `SupportedRules` gRPC; listen default `:9650` (`REDACTION_GRPC_ADDR`).
