# AGENTS.md — data-redaction-pattern

MuxCore sidecar module (`data-redaction-pattern`). Workspace deploy and SSH: [`../AGENTS.md`](../AGENTS.md). Default ports: [`_mvp/PORTS.md`](../_mvp/PORTS.md).

## Module identity

| Field | Value |
|-------|-------|
| Directory | `data-redaction-pattern` |
| Capabilities | `data.redaction`, `settings` |
| Contracts | `DataRedactionProvider` (`muxcore.json`) |

## Agent rules

- Modules run as gRPC sidecars; capabilities are the security boundary.
- TLS required in production (`MUXCORE_INSECURE_DISABLE_TLS` is dev-only).
- Match existing Go patterns; run `gofmt` and package tests before finishing.
- Cross-module events: prefer `github.com/Muxcore-Media/contracts-media/events` over deprecated `core/pkg/contracts` aliases.
- Do not edit polluted workspace dumps (see `MASTER-ROADMAP.md` Appendix H).

## Build

```bash
cd data-redaction-pattern
nix-shell -p go golangci-lint --run 'go test ./... && golangci-lint run ./...'
```

## MVP soak

Enable with `MVP_ENABLE_DATA_REDACTION=1` in `_mvp/.env`.
