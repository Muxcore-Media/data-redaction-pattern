# Data Redaction Pattern

Field-name segment, path, and regex based PII redaction provider for MuxCore.

A gRPC sidecar module that recursively redacts JSON objects using configurable rules — field name segment matching, exact nested paths, and regex value patterns. Without this module, core has no structured data redaction capability. Matched values are replaced with `***REDACTED***`.

## Key Features

- **Three rule types** — `field:<name>` (case-insensitive segment key match), `path:<a.b.c>` (exact nested path), `/<regex>/` (string value pattern). Bare strings (no prefix) are treated as `field:` rules.
- **Default sensitive keys** — Automatically redacts keys matching well-known sensitive field names from `contracts.SensitiveLogFieldNames()` plus `email`, `ip`, and `ip_address`. Segment matching avoids false positives (e.g. `auth` does not redact `author`).
- **Built-in regex rules** — Email and IPv4 patterns applied on every `Redact` call.
- **Recursive traversal** — Walks nested maps and arrays (including string elements) to apply rules at every level.
- **Live settings** — Admin-ui can update `extra_keys` and `extra_rules` without restart.
- **gRPC API** — `Redact` and `SupportedRules` RPCs; `SupportedRules` lists active default/extra keys and configured rules.

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `REDACTION_GRPC_ADDR` | `:9655` | Module gRPC listen address |
| `REDACTION_EXTRA_KEYS` | *(empty)* | Comma-separated extra field-name segments to redact |
| `REDACTION_EXTRA_RULES` | *(empty)* | Comma-separated path/regex/field rules merged into every `Redact` call |
| `MUXCORE_MODULE_ID` | `data-redaction-pattern` | Module identity (SDK / registration) |
| `MUXCORE_GRPC_ADDR` | *(required)* | Core mesh address |
| `MUXCORE_INSECURE_DISABLE_TLS` | `false` | Set `true` to disable TLS (dev only) |
| `MVP_ENABLE_DATA_REDACTION` | `0` | Enable in `_mvp/run-host.sh` soak stack |

## Usage

```bash
make build
export MUXCORE_GRPC_ADDR=localhost:9090
export MUXCORE_INSECURE_DISABLE_TLS=true
./data-redaction-pattern
```

### From Go (mesh client)

Dial the sidecar and use `pkg/client` — it implements `contracts.DataRedactionProvider`:

```go
import (
    "context"
    redactionclient "github.com/Muxcore-Media/data-redaction-pattern/pkg/client"
    "google.golang.org/grpc"
)

conn, _ := grpc.NewClient("127.0.0.1:9655", grpc.WithTransportCredentials(insecureCreds))
client := redactionclient.New(conn)

redacted, err := client.Redact(ctx, map[string]any{
    "password": "secret",
    "title":    "Movie",
}, []string{"field:credit_card"})
```

## Contract

Implements `DataRedactionProvider` (`pkg/contracts`). Registers capabilities: `data.redaction`, `settings`.
