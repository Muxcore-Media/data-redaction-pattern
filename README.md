# Data Redaction Pattern

Field-name prefix, path, and regex based PII redaction provider for MuxCore.

A gRPC sidecar module that recursively redacts JSON objects using configurable rules — field name substring matching, exact nested paths, and regex value patterns. Without this module, core has no structured data redaction capability. Matched values are replaced with `***REDACTED***`.

## Key Features

- **Three rule types** — `field:<name>` (case-insensitive substring key match), `path:<a.b.c>` (exact nested path), `/<regex>/` (string value pattern). Bare strings (no prefix) are treated as `field:` rules.
- **Default sensitive keys** — Automatically redacts keys containing well-known sensitive field names from `contracts.SensitiveLogFieldNames()`
- **Recursive traversal** — Walks nested maps and arrays to apply rules at every level
- **gRPC API** — `Redact` and `SupportedRules` RPCs

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `REDACTION_GRPC_ADDR` | `:9655` | Module gRPC listen address |
| `MUXCORE_MODULE_ID` | `data-redaction-pattern` | Module identity (SDK / registration) |
| `MUXCORE_GRPC_ADDR` | *(required)* | Core mesh address |
| `MUXCORE_INSECURE_DISABLE_TLS` | `false` | Set `true` to disable TLS (dev only) |

## Usage

```bash
make build
export MUXCORE_GRPC_ADDR=localhost:9090
export MUXCORE_INSECURE_DISABLE_TLS=true
./data-redaction-pattern
```

## Contract

Implements `DataRedactionProvider` (`pkg/contracts`). Registers capability: `data.redaction`.
