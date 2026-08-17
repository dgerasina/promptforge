"""Private lock-and-file supervisor for one local PromptForge workspace."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import stat
import time

from promptforge.platform.workspace import _LOCK, _RUNTIME, _STOP, _atomic_json
from promptforge.platform.secure_filesystem import SECURE_FILESYSTEM

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised on native Windows
    fcntl = None  # type: ignore[assignment]
    import msvcrt


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--manifest-digest", required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    supplied_state = Path(arguments.state_root).absolute()
    current = Path(supplied_state.anchor)
    for part in supplied_state.parts[1:]:
        current = current / part
        if current.is_symlink():
            return 2
    state = supplied_state.resolve(strict=True)
    try:
        SECURE_FILESYSTEM.require_private_directory(state)
    except (PermissionError, ValueError):
        return 2
    runtime_path = state / _RUNTIME
    lock_path = state / _LOCK
    stop_path = state / _STOP
    running = True

    def stop_signal(_signum: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop_signal)
    signal.signal(signal.SIGINT, stop_signal)
    lock_descriptor = os.open(
        lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600,
    )
    if os.fstat(lock_descriptor).st_size == 0:
        os.write(lock_descriptor, b"0")
        os.fsync(lock_descriptor)
    if os.name == "nt":
        SECURE_FILESYSTEM.windows.apply_and_verify(lock_path, directory=False)
    else:
        lock_metadata = os.fstat(lock_descriptor)
        if stat.S_IMODE(lock_metadata.st_mode) != 0o600 or lock_metadata.st_uid != os.getuid():
            os.close(lock_descriptor)
            return 2
    try:
        if fcntl is None:
            os.lseek(lock_descriptor, 0, os.SEEK_SET)
            msvcrt.locking(lock_descriptor, msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(lock_descriptor)
        return 2
    try:
        runtime = {
            "schema_version": "1.0", "instance_id": arguments.instance_id,
            "manifest_digest": arguments.manifest_digest, "pid": os.getpid(),
        }
        _atomic_json(runtime_path, runtime)
        runtime_identity = (runtime_path.lstat().st_dev, runtime_path.lstat().st_ino)
        while running:
            if stop_path.exists() and not stop_path.is_symlink():
                try:
                    request = json.loads(stop_path.read_text(encoding="utf-8"))
                except (OSError, ValueError, json.JSONDecodeError):
                    request = None
                if isinstance(request, dict) and request.get("instance_id") == arguments.instance_id:
                    running = False
                    break
            time.sleep(0.05)
    finally:
        os.close(lock_descriptor)
        for path, identity in ((runtime_path, locals().get("runtime_identity")),):
            try:
                current = path.lstat()
                if identity == (current.st_dev, current.st_ino):
                    path.unlink()
            except FileNotFoundError:
                pass
        try:
            if stop_path.exists() and not stop_path.is_symlink():
                stop_path.unlink()
        except FileNotFoundError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
