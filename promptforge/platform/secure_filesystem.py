"""Cross-platform owner-private filesystem primitives."""

from __future__ import annotations

from dataclasses import dataclass
import json
import ntpath
import os
from pathlib import Path
import stat
import subprocess
from typing import Callable, Mapping


Runner = Callable[[tuple[str, ...], dict[str, str]], str]
_SYSTEM_SID = "S-1-5-18"


def _powershell_runner(arguments: tuple[str, ...], environment: dict[str, str]) -> str:
    inherited = {
        key: os.environ[key] for key in (
            "SystemRoot", "WINDIR", "PATH", "PATHEXT", "ComSpec", "PSModulePath", "TEMP", "TMP",
        ) if key in os.environ
    }
    completed = subprocess.run(
        arguments, env={**inherited, **environment}, check=True, capture_output=True, text=True,
        encoding="utf-8", errors="strict", timeout=30,
    )
    return completed.stdout


@dataclass(frozen=True)
class WindowsAclBackend:
    """Applies and verifies an exact current-user + SYSTEM protected DACL."""

    runner: Runner = _powershell_runner
    executable: Path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / \
        "WindowsPowerShell" / "v1.0" / "powershell.exe"
    script: Path = Path(__file__).with_name("windows-secure-path.ps1")

    def apply_and_verify(self, path: Path, *, directory: bool) -> None:
        candidate = Path(path)
        if not ntpath.isabs(str(candidate)):
            raise ValueError("secure Windows path must be absolute")
        output = self.runner(
            (str(self.executable), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", str(self.script)),
            {"PF_SECURE_PATH": str(candidate), "PF_SECURE_KIND": "directory" if directory else "file"},
        )
        try:
            payload = json.loads(output)
        except json.JSONDecodeError as error:
            raise PermissionError("Windows ACL verification failed") from error
        expected = {"schema_version", "status", "owner", "protected", "reparse_point", "allowed_sids"}
        allowed = payload.get("allowed_sids") if isinstance(payload, Mapping) else None
        if (
            not isinstance(payload, Mapping) or set(payload) != expected or payload.get("schema_version") != "1.0"
            or payload.get("status") != "secure" or payload.get("owner") != "current-user"
            or payload.get("protected") is not True or payload.get("reparse_point") is not False
            or not isinstance(allowed, list) or set(allowed) != {"current-user", _SYSTEM_SID} or len(allowed) != 2
        ):
            raise PermissionError("Windows ACL is not owner-private")

    @staticmethod
    def _security_attributes() -> tuple[object, object]:  # pragma: no cover - native Windows only
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            raise OSError("Windows identity token is unavailable")
        try:
            needed = wintypes.DWORD()
            advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
            buffer = ctypes.create_string_buffer(needed.value)
            if not advapi32.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
                raise OSError("Windows identity SID is unavailable")
            sid_pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
            sid_text = wintypes.LPWSTR()
            if not advapi32.ConvertSidToStringSidW(sid_pointer, ctypes.byref(sid_text)):
                raise OSError("Windows identity SID conversion failed")
            sid = sid_text.value
            kernel32.LocalFree(sid_text)
        finally:
            kernel32.CloseHandle(token)
        descriptor = ctypes.c_void_p()
        sddl = f"O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)"
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None,
        ):
            raise OSError("Windows private security descriptor is unavailable")

        class SecurityAttributes(ctypes.Structure):
            _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p), ("inherit", wintypes.BOOL)]

        attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False)
        return attributes, descriptor

    def create_directory(self, path: Path) -> None:  # pragma: no cover - native Windows only
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        attributes, descriptor = self._security_attributes()
        try:
            if not kernel32.CreateDirectoryW(str(path), ctypes.byref(attributes)):
                error = ctypes.get_last_error()
                if error != 183:
                    raise OSError(error, "Windows private directory creation failed")
        finally:
            kernel32.LocalFree(descriptor)
        self.apply_and_verify(path, directory=True)

    def write_new_private(self, path: Path, content: bytes) -> None:  # pragma: no cover - native Windows only
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.restype = wintypes.HANDLE
        attributes, descriptor = self._security_attributes()
        handle = ctypes.c_void_p(-1).value
        try:
            handle = kernel32.CreateFileW(
                str(path), 0x40000000, 0, ctypes.byref(attributes), 1, 0x80, None,
            )
            if handle == ctypes.c_void_p(-1).value:
                error = ctypes.get_last_error()
                if error in {80, 183}:
                    raise FileExistsError(error, "Windows private file already exists", str(path))
                raise OSError(error, "Windows private file creation failed")
            written = wintypes.DWORD()
            payload = ctypes.create_string_buffer(content)
            if not kernel32.WriteFile(handle, payload, len(content), ctypes.byref(written), None) \
                    or written.value != len(content) or not kernel32.FlushFileBuffers(handle):
                raise OSError("Windows private file write failed")
        finally:
            if handle != ctypes.c_void_p(-1).value:
                kernel32.CloseHandle(handle)
            kernel32.LocalFree(descriptor)
        self.apply_and_verify(path, directory=False)


@dataclass(frozen=True)
class SecureFilesystem:
    """Selects POSIX modes or Windows ACLs without weakening either contract."""

    platform: str = "windows" if os.name == "nt" else "posix"
    windows: WindowsAclBackend = WindowsAclBackend()

    def ensure_private_directory(self, path: Path) -> None:
        candidate = Path(path)
        if self.platform == "windows":
            if candidate.exists():
                self.windows.apply_and_verify(candidate, directory=True)
            else:
                self.windows.create_directory(candidate)
        else:
            candidate.mkdir(mode=0o700, parents=False, exist_ok=True)
            os.chmod(candidate, 0o700)
            self.require_private_directory(candidate)

    def require_private_directory(self, path: Path) -> None:
        candidate = Path(path)
        if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_dir() \
                or candidate.resolve() != candidate:
            raise ValueError("private directory is invalid")
        if self.platform == "windows":
            self.windows.apply_and_verify(candidate, directory=True)
            return
        metadata = candidate.stat()
        owner_ok = not hasattr(os, "getuid") or metadata.st_uid == os.getuid()
        if stat.S_IMODE(metadata.st_mode) != 0o700 or not owner_ok:
            raise PermissionError("private directory permissions are invalid")

    def write_new_private(self, path: Path, content: bytes) -> None:
        candidate = Path(path)
        self.require_private_directory(candidate.parent)
        if self.platform == "windows":
            self.windows.write_new_private(candidate, content)
            return
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(candidate, flags, 0o600)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            os.write(descriptor, content)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def require_private_file(self, path: Path, maximum: int, *, allow_empty: bool = False) -> None:
        candidate = Path(path)
        if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_file() \
                or candidate.resolve() != candidate:
            raise ValueError("private file is invalid")
        metadata = candidate.stat()
        minimum = 0 if allow_empty else 1
        if not minimum <= metadata.st_size <= maximum:
            raise ValueError("private file size is invalid")
        if self.platform == "windows":
            self.windows.apply_and_verify(candidate, directory=False)
            return
        owner_ok = not hasattr(os, "getuid") or metadata.st_uid == os.getuid()
        if stat.S_IMODE(metadata.st_mode) != 0o600 or not owner_ok:
            raise PermissionError("private file permissions are invalid")

    def require_trusted_file(self, path: Path, maximum: int) -> None:
        """Validates public trust material: immutable to others, exact ACL on Windows."""

        candidate = Path(path)
        if self.platform == "windows":
            self.require_private_file(candidate, maximum)
            return
        if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_file() \
                or candidate.resolve() != candidate:
            raise ValueError("trusted file is invalid")
        metadata = candidate.stat()
        owner_ok = not hasattr(os, "getuid") or metadata.st_uid == os.getuid()
        if not 1 <= metadata.st_size <= maximum or metadata.st_mode & 0o022 or not owner_ok:
            raise PermissionError("trusted file permissions are invalid")

    def read_trusted(self, path: Path, maximum: int) -> bytes:
        self.require_trusted_file(path, maximum)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            content = os.read(descriptor, maximum + 1)
            if len(content) != metadata.st_size:
                raise ValueError("trusted file changed while reading")
            return content
        finally:
            os.close(descriptor)

    def read_private(self, path: Path, maximum: int) -> bytes:
        self.require_private_file(path, maximum)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            metadata = os.fstat(descriptor)
            content = os.read(descriptor, maximum + 1)
            if len(content) != metadata.st_size:
                raise ValueError("private file changed while reading")
            return content
        finally:
            os.close(descriptor)


SECURE_FILESYSTEM = SecureFilesystem()
