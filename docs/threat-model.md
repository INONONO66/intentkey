# Threat model

## Security objective

An agent can request authenticated actions without credential plaintext entering
model context, tool arguments or results, transcripts, observations, artifacts,
screenshots, or debug output.

## Trusted computing base

- `intentkeyd`;
- the selected credential provider;
- the selected injector;
- the owner approval surface;
- the operating-system IPC and process isolation mechanisms.

The agent runtime, model provider, target website, and ordinary application logs
are not trusted with credential plaintext.

## Claims

A setup or use claim is:

- opaque and unguessable;
- bound to an exact target and operation;
- short-lived;
- single-use;
- safe to expose to an agent only for its declared operation.

A claim is authorization metadata, not encrypted credential material.

## Browser requirement

Secure browser injection requires a privileged extension or native host that:

- revalidates the exact origin immediately before injection;
- binds the operation to an owned browser session;
- redacts secret fields from DOM and accessibility snapshots;
- masks screenshots;
- excludes secret request bodies from network and debug logs;
- denies arbitrary evaluation capable of reading injected fields;
- returns only a typed receipt.

Without those controls, filling a password input does not prevent browser
automation from reading it back.

## Out of scope for the initial milestone

- protecting against a fully compromised operating-system account;
- provider or target compromise;
- browser injection;
- durable credential storage.
