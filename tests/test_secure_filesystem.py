from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from promptforge.platform.secure_filesystem import SecureFilesystem, WindowsAclBackend


class SecureFilesystemTest(unittest.TestCase):
    def test_windows_acl_applies_exact_current_sid_and_system_contract(self) -> None:
        calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

        def runner(arguments: tuple[str, ...], environment: dict[str, str]) -> str:
            calls.append((arguments, environment))
            return json.dumps({
                "schema_version": "1.0", "status": "secure", "owner": "current-user",
                "protected": True, "reparse_point": False,
                "allowed_sids": ["current-user", "S-1-5-18"],
            })

        backend = WindowsAclBackend(runner=runner, executable=Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"))
        backend.apply_and_verify(Path("C:/private/state"), directory=True)

        self.assertEqual(1, len(calls))
        arguments, environment = calls[0]
        self.assertNotIn("C:/private/state", arguments)
        self.assertEqual("C:/private/state", environment["PF_SECURE_PATH"])
        self.assertEqual("directory", environment["PF_SECURE_KIND"])
        self.assertNotIn("secret", json.dumps(calls))
        self.assertTrue(backend.executable.is_absolute() or str(backend.executable).startswith("C:/"))

    def test_windows_creation_delegates_before_python_writes_content(self) -> None:
        class Backend:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str, bytes]] = []

            def create_directory(self, path: Path) -> None:
                self.calls.append(("directory", str(path), b""))
                path.mkdir()

            def write_new_private(self, path: Path, content: bytes) -> None:
                self.calls.append(("file", str(path), content))

            def apply_and_verify(self, path: Path, *, directory: bool) -> None:
                self.calls.append(("verify", str(path), b""))

        backend = Backend()
        filesystem = SecureFilesystem(platform="windows", windows=backend)  # type: ignore[arg-type]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target_directory = root / "private"
            filesystem.ensure_private_directory(target_directory)
            filesystem.write_new_private(target_directory / "secret", b"opaque")
        self.assertEqual(
            [("directory", str(target_directory), b""), ("verify", str(target_directory), b""),
             ("file", str(target_directory / "secret"), b"opaque")],
            backend.calls,
        )

    def test_windows_acl_fails_closed_on_inheritance_extra_sid_or_reparse(self) -> None:
        cases = (
            {"protected": False, "allowed_sids": ["current-user", "S-1-5-18"], "reparse_point": False},
            {"protected": True, "allowed_sids": ["current-user", "S-1-5-18", "S-1-5-32-545"], "reparse_point": False},
            {"protected": True, "allowed_sids": ["current-user", "S-1-5-18"], "reparse_point": True},
        )
        for case in cases:
            payload = {
                "schema_version": "1.0", "status": "secure", "owner": "current-user", **case,
            }
            backend = WindowsAclBackend(
                runner=lambda _arguments, _environment, value=json.dumps(payload): value,
                executable=Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"),
            )
            with self.subTest(case=case), self.assertRaises(PermissionError):
                backend.apply_and_verify(Path("C:/private/state"), directory=True)

    def test_posix_backend_preserves_private_directory_and_file_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "state"
            filesystem = SecureFilesystem(platform="posix")
            filesystem.ensure_private_directory(root)
            target = root / "secret.txt"
            filesystem.write_new_private(target, b"opaque")
            self.assertEqual(b"opaque", filesystem.read_private(target, 100))
            filesystem.require_private_directory(root)
            filesystem.require_private_file(target, 100)


if __name__ == "__main__":
    unittest.main()
