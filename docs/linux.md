# Linux artifacts and native vault

## Verification status and contents

The `linux-artifacts` workflow targets a **native Ubuntu 24.04 x86_64 runner**
and `x86_64-unknown-linux-musl`. ARM64 Linux artifacts are not currently built.
The workflow is source-only until its Linux CI job succeeds; macOS smoke results
are not Linux or x86_64 execution evidence. Use only an artifact from a successful
job for the intended commit, not an unverified local build.

Each `intentkey-VERSION-x86_64-unknown-linux-musl-COMMIT.tar.gz` contains:

- `intentkey` and `intentkeyd`, mode 0755, built without `test-harness`;
- `LICENSE-MIT`, `LICENSE-APACHE`, `README.md`, and Linux/threat-model docs;
- `BUILD-INFO` with full commit SHA, target, package version, and Rust version;
- `SHA256SUMS` for the contents, plus an adjacent archive `.sha256` file.

CI builds both adjacent test binaries and runs all-feature musl-target tests in
one target directory. It builds production release binaries in a different
directory with `--no-default-features`. It then extracts the archive, verifies
checksums, permissions, ELF64/x86_64 architecture, and absence of `INTERP` and
`NEEDED`, and runs **those exact extracted binaries** through
`scripts/linux-smoke.py`. Upload runs only after all gates succeed.

The smoke uses Python 3.12+ (stdlib only), isolated mode-0700 HOME/XDG/temp
storage, random inert private inputs, concurrent inherited-pipe writes, bounded
process cleanup, and stderr readiness events rather than sleeps. It checks
versions, rejected test-only flags, native custody lifecycle/restart, metadata,
unsupported `sign_in`, and plaintext-marker absence in captured output and temp
files. This does not prove protection against memory inspection or every encoding
of a secret. It contacts no live provider or server.

## Download, verify, and install locally

Download the archive and matching checksum from the successful workflow's
artifact. In the directory containing them, set `archive` to the actual filename:

```sh
archive='intentkey-VERSION-x86_64-unknown-linux-musl-COMMIT.tar.gz'
sha256sum -c "$archive.sha256"
mkdir -p unpacked
tar -xzf "$archive" -C unpacked
package="$(pwd)/unpacked/${archive%.tar.gz}"
(cd "$package" && sha256sum -c SHA256SUMS)
install -d -m 0755 "$HOME/.local/bin"
install -m 0755 "$package/intentkey" "$package/intentkeyd" "$HOME/.local/bin/"
export PATH="$HOME/.local/bin:$PATH"
intentkey --version
intentkeyd --version
```

Checksums detect corruption, not provenance: trust the workflow/repository source
separately. Native custody needs a writable local filesystem with Unix
permissions, file locking, atomic rename, and directory synchronization. Run as
an unprivileged owner, not root. Same-UID processes are inside the owner's trust
boundary; do not place untrusted agents under that UID expecting OS isolation.

## Exact bootstrap and restart/unlock

The daemon runs in the foreground. In terminal A, create **dedicated** private
directories; never chmod a shared directory to make startup pass:

```sh
umask 077
export INTENTKEY_SOCKET="${XDG_RUNTIME_DIR:-$HOME/.intentkey-runtime}/intentkey/agent.sock"
export INTENTKEY_DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/intentkey"
mkdir -p "$(dirname "$INTENTKEY_SOCKET")" "$INTENTKEY_DATA_DIR"
# Existing socket/data directories must already be owned by you and mode 0700.
stat -c '%U %a %n' "$(dirname "$INTENTKEY_SOCKET")" "$INTENTKEY_DATA_DIR"
intentkeyd --socket "$INTENTKEY_SOCKET" --data-dir "$INTENTKEY_DATA_DIR"
```

`INTENTKEY_DATA_DIR` above is a shell variable passed to `--data-dir`, not a daemon
configuration environment variable. Keep the durable data directory when runtime
storage is cleared. Symlinked or unsafe storage paths are rejected; use canonical
absolute paths and a short socket path (Unix socket path lengths are limited).

In terminal B, set the **same socket path**, then initialize once:

```sh
export INTENTKEY_SOCKET="${XDG_RUNTIME_DIR:-$HOME/.intentkey-runtime}/intentkey/agent.sock"
intentkey status
intentkey vault init
intentkey vault store --kind password
intentkey vault list
intentkey vault lock
```

All owner commands prompt on `/dev/tty` with echo disabled. `init` asks for a
passphrase and confirmation and starts unlocked; `store` asks for the passphrase
and private value. `list` emits opaque metadata, never stored values. Re-running
`init` refuses to overwrite an existing vault. Do not use shell arguments,
environment variables, command substitution, or plaintext temp files for secrets.
There is no reveal/export command.

Stop terminal A's daemon with Ctrl-C. After starting it again with the same
socket and data paths, custody is locked:

```sh
intentkey vault unlock
intentkey vault list
```

Enter the existing passphrase at the private prompt. Wrong authentication fails
closed and drops custody; a later successful `unlock` is required. Every owner
operation authenticates. For mutations, copy only the opaque `item_id` and exact
current numeric `revision` from `vault list`:

```sh
intentkey vault update --item-id "$item_id" --revision "$revision"
# Re-read metadata after update; stale revisions are rejected.
intentkey vault list
intentkey vault remove --item-id "$item_id" --revision "$revision"
intentkey vault generate
intentkey vault lock
```

`update` privately prompts for the replacement value; `remove` deletes that exact
revision. Set the shell variables to the actual metadata before running either.
`generate` creates bearer material without revealing it. Native password/bearer
custody currently has no privileged consumer: metadata does **not** authorize a
dummy `sign_in` or hand credential bytes to agents.

For trusted automation, `intentkey vault --secret-fd N ...` accepts an inherited
pipe or Unix socket fd **>=3**, not stdin or a regular file. Frames are a 4-byte
big-endian length followed by raw passphrase bytes, then a second such frame for
`store`/`update`, followed by EOF. Passphrases are 1..1024 bytes; values are
1..65536 bytes. Feed concurrently with the child to avoid pipe-capacity deadlock.
This private owner channel is not an agent/tool protocol. The smoke script is an
inert example, not a credential export utility.

## Vendor CLI prerequisites and limits

Native custody does not require a vendor CLI. The musl archive does not bundle
1Password CLI (`op`) or Proton Pass CLI (`pass-cli`), and static linking IntentKey
does not remove those external executables' own OS/library requirements.
Install a supported Linux build from the vendor, configure its account/session
using its documented trusted-owner flow, and verify its executable path and
permissions before any future provider setup:

- 1Password CLI: <https://developer.1password.com/docs/cli/get-started/>
- Proton Pass CLI: <https://protonpass.github.io/pass-cli/>

Provider adapters are still integration work; this document does not claim a
shipped provider setup command or give speculative CLI syntax. Do not supply
provider sessions or live credentials to artifact smoke tests. No remote server
deployment, service installation, or live provider login is performed by this
workflow.
