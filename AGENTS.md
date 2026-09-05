# IntentKey agent guide

IntentKey lets agents use credentials without receiving credential plaintext.

## Non-negotiable invariants

- Never place plaintext credentials in protocol messages, links, logs, errors,
  receipts, tests, snapshots, or command arguments.
- Model-facing APIs expose metadata, opaque references, and receipts only.
- Links contain short-lived, audience-bound, single-use claims, never secrets.
- Providers retrieve secrets; injectors consume them. Only the privileged
  daemon may connect these sides.
- There is no general reveal API.
- Reject ambiguous targets. Browser use requires an exact HTTP(S) origin.

## Workspace

- `crates/intentkey-core`: protocol vocabulary and pure claim issuance.
- `crates/intentkeyd`: privileged local daemon and admission boundary.
- `crates/intentkey`: owner/agent CLI client.

## Required checks

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --workspace -- -D warnings
cargo nextest run --all-targets --all-features --workspace
cargo deny check
```

Write behavior tests first. Do not assert prose; assert typed protocol values.
