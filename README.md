# Data Redaction Pattern

Field-name prefix, path, and regex based PII redaction provider for MuxCore.

A gRPC sidecar module that recursively redacts JSON data using configurable rules — field prefix matching, exact nested paths, and regex value patterns. Without this module, core has no structured data redaction capability.

## Key Features

- **Three rule types** — `field:<name>` (case-insensitive key match), `path:<a.b.c>` (nested path), `/<regex>/` (value pattern match)
- **Default sensitive keys** — Automatically redacts well-known sensitive field names from the core contracts
- **Recursive traversal** — Walks nested maps and arrays to apply rules at every level
- **gRPC API** — `Redact` and `SupportedRules` RPCs

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `REDACTION_GRPC_ADDR` | `:9650` | gRPC listen address |
| `MUXCORE_MODULE_ID` | `data-redaction-pattern` | Module identity |

## Usage

```bash
export MUXCORE_GRPC_INSECURE=true
data-redaction-pattern
```

## Contract

Implements `DataRedactionProvider` (`pkg/contracts`). Registers capability: `data.redaction`.
