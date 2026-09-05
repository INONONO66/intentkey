# IntentKey

**Give agents permission to act, not secrets to hold.**

IntentKey is an agent-native credential runtime. Agents request an intent;
IntentKey authorizes the action and injects credentials directly into the
target without exposing plaintext to model context.

```text
1Password ─┐
pass       ─┤
Keychain   ─┼─> intentkeyd ─> Browser
OpenBao    ─┤               ├> HTTP
Built-in   ─┘               ├> Process
                            └> SSH / MCP
```

## Current milestone

The first milestone establishes the process boundary and safe handoff protocol:

- `intentkeyd`: a local Unix-socket daemon;
- `intentkey`: an owner and agent CLI;
- exact-origin, short-lived, single-use setup claims;
- handoff links that contain a capability, never credential plaintext;
- machine-readable receipts suitable for agent runtimes.

Provider adapters and browser injection land behind this protocol. Until an
injector exists, IntentKey does not claim to protect values from a browser
automation surface.

## Quick start

```bash
cargo run -p intentkeyd
cargo run -p intentkey -- status
cargo run -p intentkey -- setup \
  --origin https://github.com \
  --action account_signup \
  --kind login
```

The setup command returns a loopback handoff URL. The URL fragment carries a
single-use claim ID; it never carries a username, password, token, or payment
value.

## Security model

The model-facing process receives only:

- safe credential metadata;
- opaque references;
- intent grants;
- metadata-only receipts.

Plaintext may exist only inside a provider or privileged injector boundary. A
general `credential.read` or `vault.reveal` API is forbidden. See
[`docs/threat-model.md`](docs/threat-model.md).

## Status

IntentKey is pre-alpha and not ready for production credentials.

## License

Licensed under either Apache-2.0 or MIT, at your option.
