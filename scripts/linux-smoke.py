#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# How to run (stdlib only; also supports uv run):
# python3 scripts/linux-smoke.py --cli /extracted/intentkey --daemon /extracted/intentkeyd
"""Exercise extracted production custody, never live credentials or providers."""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import secrets
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Final, final

TIMEOUT: Final = 120.0
REAP_TIMEOUT: Final = 10.0
type Json = None | bool | int | str | list[Json] | dict[str, Json]
# The stdlib decoder boundary returns precisely the JSON value vocabulary.
decode: Callable[[bytes], Json] = json.loads


class SmokeFailure(RuntimeError):
    """An assertion containing only a trusted source-code label."""


def check(condition: bool, label: str) -> None:
    """Report only a trusted assertion label, never a response or private bytes."""
    if not condition:
        raise SmokeFailure(label)


@final
class Smoke:
    """Own mutable process captures and one isolated native-vault lifecycle."""

    def __init__(self, cli: Path, daemon: Path, root: Path) -> None:
        self.cli, self.daemon, self.root = cli, daemon, root
        self.socket = root / "runtime/agent.sock"
        self.env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(root / "home"),
            "XDG_DATA_HOME": str(root / "data"),
            "XDG_RUNTIME_DIR": str(root / "runtime"),
            "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_CACHE_HOME": str(root / "cache"),
            "TMPDIR": str(root / "tmp"),
            "NO_COLOR": "1",
            "RUST_LOG": "intentkeyd=info",
        }
        for name in ("home", "runtime", "data", "config", "cache", "tmp"):
            (root / name).mkdir(mode=0o700)
        self.private = tuple(secrets.token_hex(n).encode() for n in (16, 16, 32768, 64))
        # Scan both complete inputs and their independently random 32-byte prefixes.
        self.markers = self.private + tuple(value[:32] for value in self.private)
        self.captures: list[bytes] = []

    def clean(self, data: bytes) -> None:
        check(not any(marker in data for marker in self.markers), "marker_present=true")

    def scan(self) -> None:
        for path in (self.root, *self.root.rglob("*")):
            info = path.lstat()
            check(info.st_uid == os.getuid(), "temporary ownership")
            check(not stat.S_ISLNK(info.st_mode), "temporary symlink")
            if stat.S_ISDIR(info.st_mode):
                check(stat.S_IMODE(info.st_mode) == 0o700, "directory permissions")
            else:
                check(stat.S_IMODE(info.st_mode) == 0o600, "file/socket permissions")
                if stat.S_ISREG(info.st_mode):
                    self.clean(path.read_bytes())
        for data in self.captures:
            self.clean(data)

    def command(
        self, args: list[str], frames: tuple[bytes, ...] = ()
    ) -> tuple[int, bytes]:
        """Multiplex secret writes and both output pipes; never fill a pipe pre-spawn."""
        read_fd, write_fd = os.pipe()
        check(read_fd >= 3, "private fd must be >=3")
        output = [bytearray(), bytearray()]
        payload = memoryview(b"".join(len(x).to_bytes(4, "big") + x for x in frames))
        with os.fdopen(read_fd, "rb") as reader, os.fdopen(write_fd, "wb") as writer:
            command = args + (["--secret-fd", str(read_fd)] if frames else [])
            with subprocess.Popen(
                command,
                pass_fds=(read_fd,) if frames else (),
                env=self.env,
                cwd=self.root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc:
                reader.close()
                try:
                    assert proc.stdout is not None and proc.stderr is not None
                    with selectors.DefaultSelector() as events:
                        _ = events.register(proc.stdout, selectors.EVENT_READ, 0)
                        _ = events.register(proc.stderr, selectors.EVENT_READ, 1)
                        os.set_blocking(write_fd, False)
                        if payload:
                            _ = events.register(writer, selectors.EVENT_WRITE, 2)
                        else:
                            writer.close()
                        deadline = time.monotonic() + TIMEOUT
                        while events.get_map():
                            remaining = deadline - time.monotonic()
                            check(remaining > 0, "CLI deadline")
                            ready = events.select(remaining)
                            check(bool(ready), "CLI I/O deadline")
                            for event, _ in ready:
                                if event.fd == write_fd:
                                    payload = payload[os.write(write_fd, payload) :]
                                    if not payload:
                                        _ = events.unregister(writer)
                                        writer.close()
                                else:
                                    chunk = os.read(event.fd, 65536)
                                    if not chunk:
                                        _ = events.unregister(event.fileobj)
                                    index = 0 if event.fd == proc.stdout.fileno() else 1
                                    output[index].extend(chunk)
                                    check(
                                        len(output[index]) <= 1048576,
                                        "CLI output limit",
                                    )
                        code = proc.wait(
                            timeout=max(0.001, deadline - time.monotonic())
                        )
                finally:
                    if proc.poll() is None:
                        proc.kill()
                    _ = proc.wait(timeout=REAP_TIMEOUT)
                    for data in output:
                        self.captures.append(bytes(data))
                        self.clean(bytes(data))
        return code, bytes(output[0])

    def owner(
        self, args: list[str], frames: tuple[bytes, ...], expected: str = ""
    ) -> Json:
        code, raw = self.command(
            [str(self.cli), "--socket", str(self.socket), "vault", *args], frames
        )
        response = decode(raw)
        check(code == (1 if expected else 0), "owner exit status")
        if expected:
            check(
                response == {"status": "error", "output": expected}, "owner error code"
            )
        return response

    @contextmanager
    def running(self) -> Generator[None]:
        """Subscribe via a pre-created stderr pipe before launching the daemon."""
        ready: queue.Queue[bool] = queue.Queue()
        failures: list[bool] = []
        read_fd, write_fd = os.pipe()

        def drain(stream: BinaryIO, startup: bool) -> None:
            try:
                with stream:
                    for line in stream:
                        self.captures.append(line)
                        if startup and b"intentkeyd.ready" in line:
                            ready.put(True)
            except OSError:
                failures.append(True)
            finally:
                if startup:
                    ready.put(False)

        with os.fdopen(read_fd, "rb") as reader, os.fdopen(write_fd, "wb") as writer:
            stderr_thread = threading.Thread(
                target=drain, args=(reader, True), daemon=True
            )
            stderr_thread.start()
            with subprocess.Popen(
                [str(self.daemon), "--socket", str(self.socket)],
                env=self.env,
                cwd=self.root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=writer,
            ) as proc:
                writer.close()
                assert proc.stdout is not None
                stdout_thread = threading.Thread(
                    target=drain, args=(proc.stdout, False), daemon=True
                )
                stdout_thread.start()
                try:
                    check(ready.get(timeout=TIMEOUT), "daemon exited before readiness")
                    check(proc.poll() is None, "daemon died at readiness")
                    yield
                finally:
                    if proc.poll() is None:
                        proc.send_signal(signal.SIGINT)
                    try:
                        code = proc.wait(timeout=REAP_TIMEOUT)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        _ = proc.wait(timeout=REAP_TIMEOUT)
                        raise SmokeFailure("daemon shutdown deadline") from None
                    finally:
                        stderr_thread.join(REAP_TIMEOUT)
                        stdout_thread.join(REAP_TIMEOUT)
                    check(
                        not stderr_thread.is_alive() and not stdout_thread.is_alive(),
                        "capture deadline",
                    )
                    check(not failures, "daemon capture failed")
                    self.scan()
                    check(code == 0, "daemon exit status")
                    check(not self.socket.exists(), "agent socket cleanup")
                    check(
                        not self.socket.with_name("owner.sock").exists(),
                        "owner socket cleanup",
                    )

    def agent(self, request: Json) -> Json:
        raw = json.dumps(request).encode()
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(TIMEOUT)
            connection.connect(str(self.socket))
            connection.sendall(len(raw).to_bytes(4, "big") + raw)
            with connection.makefile("rb") as stream:
                header = stream.read(4)
                check(len(header) == 4, "agent frame header")
                length = int.from_bytes(header, "big")
                check(0 < length <= 65536, "agent frame bound")
                response = stream.read(length)
                check(len(response) == length, "agent frame truncated")
        self.clean(response)
        return decode(response)

    def catalog(self, items: list[Json]) -> None:
        session = self.agent({"op": "open_session"})
        assert isinstance(session, dict) and isinstance(session.get("session"), str)
        token = session["session"]
        check(
            self.agent({"op": "list_items", "input": {"session": token}})
            == {"status": "items_listed", "items": items},
            "agent metadata catalog",
        )
        for item in items:
            assert isinstance(item, dict)
            refused = self.agent(
                {
                    "op": "prepare_use",
                    "input": {
                        "session": token,
                        "item_id": item["item_id"],
                        "revision": item["revision"],
                        "intent": {
                            "action": "sign_in",
                            "target": "https://example.invalid/",
                        },
                        "operation": {"operation": "login", "variant": "password"},
                        "selected_component": "password",
                        "ttl_ms": 60000,
                    },
                }
            )
            assert isinstance(refused, dict)
            check(
                refused.get("status") == "rejected"
                and refused.get("code") == "unsupported",
                "production must not authorize dummy sign_in",
            )

    def lifecycle(self) -> None:
        password, wrong, value, replacement = self.private
        with self.running():
            code, health = self.command(
                [
                    str(self.cli),
                    "--socket",
                    str(self.socket),
                    "--format",
                    "json",
                    "status",
                ]
            )
            check(
                code == 0
                and isinstance(decoded_health := decode(health), dict)
                and decoded_health.get("status") == "healthy",
                "CLI health",
            )
            self.catalog([])
            check(
                self.owner(["init"], (password,))
                == {"status": "state", "output": "unlocked"},
                "init state",
            )
            _ = self.owner(["init"], (password,), "AlreadyInitialized")
            created = self.owner(["store", "--kind", "password"], (password, value))
            assert isinstance(created, dict) and isinstance(created["output"], dict)
            item = created["output"]
            assert isinstance(item["item_id"], str)
            item_id = item["item_id"]
            check(
                bool(re.fullmatch(r"itm_[0-9a-f]{32}", item_id)), "opaque item identity"
            )
            expected: Json = {
                "item_id": item_id,
                "revision": 1,
                "kind": {"kind": "login"},
                "login_components": [
                    {
                        "id": "password",
                        "kind": "password",
                        "provider_presence": "stored",
                        "operation_support": "unsupported",
                    }
                ],
            }
            check(
                created == {"status": "item", "output": expected},
                "stored metadata schema",
            )
            check(
                self.owner(["list"], (password,))
                == {"status": "items", "output": [expected]},
                "owner list",
            )
            self.catalog([expected])
            check(
                self.owner(["lock"], (password,))
                == {"status": "state", "output": "locked"},
                "lock state",
            )
            self.catalog([])
            _ = self.owner(["unlock"], (wrong,), "AuthenticationFailed")
            _ = self.owner(["list"], (password,), "Locked")
            check(
                self.owner(["unlock"], (password,))
                == {"status": "state", "output": "unlocked"},
                "unlock state",
            )
            _ = self.owner(
                ["update", "--item-id", item_id, "--revision", "0"],
                (password, replacement),
                "RevisionMismatch",
            )
            updated = {**item, "revision": 2}
            check(
                self.owner(
                    ["update", "--item-id", item_id, "--revision", "1"],
                    (password, replacement),
                )
                == {"status": "item", "output": updated},
                "updated metadata",
            )
            self.catalog([updated])
            self.scan()
        # Runtime deletion proves encrypted custody is durable, not SQLite/runtime-derived.
        shutil.rmtree(self.root / "runtime")
        (self.root / "runtime").mkdir(mode=0o700)
        with self.running():
            self.catalog([])
            _ = self.owner(["list"], (password,), "Locked")
            check(
                self.owner(["unlock"], (password,))
                == {"status": "state", "output": "unlocked"},
                "restart unlock",
            )
            check(
                self.owner(["list"], (password,))
                == {"status": "items", "output": [updated]},
                "restart durability",
            )
            self.catalog([updated])
            _ = self.owner(
                ["remove", "--item-id", item_id, "--revision", "1"],
                (password,),
                "RevisionMismatch",
            )
            check(
                self.owner(
                    ["remove", "--item-id", item_id, "--revision", "2"], (password,)
                )
                == {"status": "removed", "output": item_id},
                "remove identity",
            )
            check(
                self.owner(["list"], (password,)) == {"status": "items", "output": []},
                "removed catalog",
            )
            self.catalog([])
        with self.running():
            _ = self.owner(["unlock"], (password,))
            check(
                self.owner(["list"], (password,)) == {"status": "items", "output": []},
                "durable removal",
            )


class Options(argparse.Namespace):
    cli: Path = Path()
    daemon: Path = Path()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--cli", type=Path, required=True)
    _ = parser.add_argument("--daemon", type=Path, required=True)
    args = parser.parse_args(namespace=Options())
    cli, daemon = args.cli.resolve(strict=True), args.daemon.resolve(strict=True)
    for path in (cli, daemon):
        check(
            path.is_file() and stat.S_IMODE(path.stat().st_mode) == 0o755,
            "packaged executable mode",
        )
    with tempfile.TemporaryDirectory(prefix="ik-smoke-", dir="/tmp") as temporary:
        root = Path(temporary).resolve()
        root.chmod(0o700)
        smoke = Smoke(cli, daemon, root)
        try:
            versions: list[bytes] = []
            for binary in (cli, daemon):
                code, version = smoke.command([str(binary), "--version"])
                check(
                    code == 0
                    and bool(
                        re.fullmatch(
                            binary.name.encode() + rb" \d+\.\d+\.\d+[^\s]*\n", version
                        )
                    ),
                    "binary version",
                )
                versions.append(version.split()[1])
                for flag in (
                    "--test-catalog",
                    "--test-executor-log",
                    "--test-recovery-log",
                ):
                    code, _ = smoke.command([str(binary), flag, str(root / "unused")])
                    check(code == 2, "production rejected test-only flag")
            check(versions[0] == versions[1], "matching binary versions")
            smoke.lifecycle()
        finally:
            smoke.scan()
    print("production_smoke_passed=true marker_present=false")


if __name__ == "__main__":
    try:
        main()
    except SmokeFailure as error:
        print(f"production_smoke_passed=false check={error}", file=sys.stderr)
        sys.exit(1)
    except (
        OSError,
        ValueError,
        AssertionError,
        KeyError,
        IndexError,
        TypeError,
        queue.Empty,
        subprocess.SubprocessError,
    ) as error:
        # Boundary only: even malformed JSON/OS errors must never print captured bytes.
        print(
            f"production_smoke_passed=false error_type={type(error).__name__}",
            file=sys.stderr,
        )
        sys.exit(1)
