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

The agent runtime, model provider, and ordinary application logs must not receive
credential plaintext. An explicitly approved target is an authorized recipient
for its operation; protection against that recipient's compromise is excluded.

## Native vault custody

Native storage is being added after the metadata-only initial milestone.
The owner client and daemon's private secret module are trusted with plaintext.
Owner input uses a separate bounded channel, not the agent JSON protocol.
Every owner management request authenticates independently; an unlocked vault
does not turn an ordinary agent session into owner authority.

Encrypted storage and private Unix sockets do not isolate hostile processes
running with the same OS-user authority. Zeroizing buffers do not guarantee
erasure of operating-system copies, swap, or captured memory. Authenticated
encryption does not detect replay of an entire older valid vault snapshot.
Deleting a file does not prove removal from SSDs or backups.

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

## Not provided by the native-store milestone

- protecting against a fully compromised operating-system account;
- provider or target compromise;
- browser injection;
- recovery without the owner passphrase;
- whole-snapshot rollback detection or secure erasure of backups.
