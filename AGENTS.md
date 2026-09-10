# IntentKey agent guide

IntentKey lets agents use credentials without receiving credential plaintext.

## Non-negotiable invariants

- Never place plaintext credentials in agent-facing protocol messages, links,
  logs, errors, receipts, snapshots, or command arguments.
- The dedicated owner input channel is a privileged secret data plane: bounded
  raw frames carry passphrases and values directly into daemon secret custody,
  never through `DaemonRequest`, JSON metadata, or agent tool results.
- Tests use runtime-generated noncredential markers only through private test
  channels; never print their bytes or persist them as plaintext fixtures.
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
