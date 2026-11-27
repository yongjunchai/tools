"""Download the latest Cursor installer and install it over the current install.

Usage:
    python update_cursor.py              # update if a newer version exists
    python update_cursor.py --force      # reinstall even if already up to date
    python update_cursor.py --download-only
    python update_cursor.py --yes        # don't prompt before closing Cursor

Run it from a normal terminal (not Cursor's integrated terminal). If started
from inside Cursor, it relaunches itself in a separate console window because
Cursor has to be closed for the install.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
from datetime import datetime
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Iterator

API_BASE_URL = "https://cursor.com/api/download"
TRUSTED_HOSTS = ("cursor.com", ".cursor.com")
EXPECTED_SIGNER = "Anysphere, Inc."

SYSTEM_ROOT = Path(os.environ.get("SystemRoot") or r"C:\Windows")
SYSTEM32 = SYSTEM_ROOT / "System32"
POWERSHELL_EXE = SYSTEM32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
TASKKILL_EXE = SYSTEM32 / "taskkill.exe"

LOCAL_APPDATA = Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local"))
USER_INSTALL_DIR = LOCAL_APPDATA / "Programs" / "cursor"
DOWNLOAD_DIR = LOCAL_APPDATA / "cursor-updater"
DETACHED_ENV = "CURSOR_UPDATER_DETACHED"

CREATE_NEW_CONSOLE = 0x00000010
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000
DETACHED_PROCESS = 0x00000008

TH32CS_SNAPPROCESS = 0x00000002
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

_STABLE_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_SAFE_EXE_RE = re.compile(r"^[A-Za-z0-9._-]+\.exe$", re.IGNORECASE)
_TOKEN_SPLIT_RE = re.compile(r"(\d+|\D+)")


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


def _init_kernel32() -> ctypes.WinDLL | None:
    if sys.platform != "win32":
        return None
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    k32.Process32FirstW.restype = wintypes.BOOL
    k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)]
    k32.Process32NextW.restype = wintypes.BOOL
    k32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL
    return k32


_KERNEL32 = _init_kernel32()


def log(msg: str) -> None:
    ts = datetime.now().isoformat(sep=" ", timespec="milliseconds")
    print(f"[{ts}] [update-cursor] {msg}", flush=True)


def parse_version(v: str) -> tuple[tuple[int, ...], tuple]:
    """Parse a SemVer-like string so pre-releases sort before final releases."""
    cleaned = v.strip().lstrip("vV").split("+", 1)[0]
    core_str, sep, pre_str = cleaned.partition("-")

    core: list[int] = []
    for part in core_str.split("."):
        m = re.match(r"^\d+", part)
        core.append(int(m.group(0)) if m else 0)
    while len(core) > 1 and core[-1] == 0:
        core.pop()

    if not sep or not pre_str:
        # Final release sorts higher than any pre-release with the same core version.
        return (tuple(core), (1,))

    pre_tokens: list[tuple[int, int | str]] = []
    for ident in pre_str.split("."):
        for tok in _TOKEN_SPLIT_RE.findall(ident):
            if tok.isdigit():
                pre_tokens.append((0, int(tok)))
            else:
                pre_tokens.append((1, tok))
    return (tuple(core), (0, tuple(pre_tokens)))


def native_arch() -> str:
    """Return host OS architecture even if running emulated x64 Python on ARM64."""
    raw = (
        os.environ.get("PROCESSOR_ARCHITEW6432")
        or os.environ.get("PROCESSOR_ARCHITECTURE")
        or platform.machine()
    ).lower()
    return "arm64" if raw in ("arm64", "aarch64") else "x64"


def detect_install() -> tuple[Path, str]:
    """Detect existing Cursor install directory and matching API platform ID."""
    arch = native_arch()
    if (USER_INSTALL_DIR / "resources" / "app" / "product.json").is_file():
        return USER_INSTALL_DIR, f"win32-{arch}-user"

    for env_key in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env_key)
        if base:
            candidate = Path(base) / "cursor"
            if (candidate / "resources" / "app" / "product.json").is_file():
                return candidate, f"win32-{arch}"

    return USER_INSTALL_DIR, f"win32-{arch}-user"


def validate_trusted_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host:
        raise ValueError(f"Refusing non-HTTPS URL: {url!r}")
    if host != TRUSTED_HOSTS[0] and not host.endswith(TRUSTED_HOSTS[1]):
        raise ValueError(f"Refusing untrusted download host {host!r} in URL: {url!r}")


class _TrustedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        resolved = urllib.parse.urljoin(req.full_url, newurl)
        validate_trusted_url(resolved)
        return super().redirect_request(req, fp, code, msg, headers, resolved)


def _open_url(url: str, timeout: int):
    validate_trusted_url(url)
    opener = urllib.request.build_opener(_TrustedRedirectHandler())
    req = urllib.request.Request(url, headers={"User-Agent": "cursor-update-script"})
    return opener.open(req, timeout=timeout)


def is_stable_version(v: str) -> bool:
    """Return True only for final X.Y.Z stable versions (no beta/alpha/rc/nightly tags)."""
    return bool(_STABLE_VERSION_RE.fullmatch(v.strip().lstrip("vV")))


def fetch_latest_stable(platform_str: str) -> dict:
    query = urllib.parse.urlencode({"platform": platform_str, "releaseTrack": "stable"})
    url = f"{API_BASE_URL}?{query}"
    with _open_url(url, timeout=30) as resp:
        info = json.load(resp)
    if not isinstance(info, dict) or "downloadUrl" not in info or "version" not in info:
        raise RuntimeError(f"Unexpected API response: {info!r}")
    version = str(info["version"])
    if not is_stable_version(version):
        raise RuntimeError(f"Refusing non-stable release version from API: {version!r}")
    validate_trusted_url(info["downloadUrl"])
    return info


def safe_installer_name(download_url: str, version: str) -> str:
    raw_name = PurePosixPath(urllib.parse.urlparse(download_url).path).name
    if _SAFE_EXE_RE.fullmatch(raw_name):
        return raw_name
    safe_ver = re.sub(r"[^A-Za-z0-9._-]", "_", version)
    return f"CursorSetup-{safe_ver}.exe"


def installed_version(install_dir: Path) -> str | None:
    product = install_dir / "resources" / "app" / "product.json"
    try:
        return json.loads(product.read_text(encoding="utf-8"))["version"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        return None


def signature_ok(path: Path) -> bool:
    """Verify Windows Authenticode signature without interpolating path into script code."""
    if not POWERSHELL_EXE.is_file():
        raise RuntimeError(f"PowerShell executable not found at {POWERSHELL_EXE}")

    ps_script = (
        "$ErrorActionPreference = 'Stop'; "
        "$s = Get-AuthenticodeSignature -LiteralPath $env:CURSOR_VERIFY_PATH; "
        "$cn = if ($s.SignerCertificate) { "
        "$s.SignerCertificate.GetNameInfo('SimpleName', $false) "
        "} else { '' }; "
        "\"$($s.Status)|$cn\""
    )
    env = dict(os.environ, CURSOR_VERIFY_PATH=str(path))
    result = subprocess.run(
        [str(POWERSHELL_EXE), "-NoProfile", "-NonInteractive", "-Command", ps_script],
        capture_output=True,
        text=True,
        env=env,
        close_fds=True,
    )
    out = result.stdout.strip()
    status, _, signer_cn = out.partition("|")
    if result.returncode != 0 or status != "Valid" or signer_cn != EXPECTED_SIGNER:
        log(f"Signature check failed for {path.name}: status={status!r}, signer={signer_cn!r}")
        return False
    return True


@contextmanager
def read_lock(path: Path) -> Iterator[None]:
    """Hold an OS-level read-only share lock so the file cannot be modified or replaced."""
    if _KERNEL32 is None:
        yield
        return
    handle = _KERNEL32.CreateFileW(
        str(path),
        GENERIC_READ,
        FILE_SHARE_READ,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        raise OSError(err, f"Unable to lock {path} for verification (WinError {err})")
    try:
        yield
    finally:
        _KERNEL32.CloseHandle(handle)


def download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + f".{os.getpid()}.part")
    try:
        with _open_url(url, timeout=60) as resp, open(tmp, "wb") as f:
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            last_print = 0.0
            while chunk := resp.read(1024 * 256):
                f.write(chunk)
                done += len(chunk)
                now = time.monotonic()
                if now - last_print > 0.5 or (total and done == total):
                    last_print = now
                    if total:
                        pct = done * 100 / total
                        print(
                            f"\r  {done / 2**20:7.1f} / {total / 2**20:.1f} MB ({pct:5.1f}%)",
                            end="",
                            flush=True,
                        )
                    else:
                        print(f"\r  {done / 2**20:7.1f} MB", end="", flush=True)
        print()
        if total and done != total:
            raise RuntimeError(f"Incomplete download: got {done} of {total} bytes")
        tmp.replace(dest)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def process_table() -> dict[int, tuple[int, str]]:
    """Return {pid: (parent_pid, exe_name)} for all running processes via Win32 snapshot."""
    if _KERNEL32 is None:
        return {}
    snap = _KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        raise OSError(err, f"CreateToolhelp32Snapshot failed (WinError {err})")
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
        table: dict[int, tuple[int, str]] = {}
        if _KERNEL32.Process32FirstW(snap, ctypes.byref(entry)):
            while True:
                table[int(entry.th32ProcessID)] = (int(entry.th32ParentProcessID), entry.szExeFile)
                if not _KERNEL32.Process32NextW(snap, ctypes.byref(entry)):
                    break
        return table
    finally:
        _KERNEL32.CloseHandle(snap)


def pids_by_name(*names: str) -> list[int]:
    targets = {n.lower() for n in names}
    return [pid for pid, (_, exe) in process_table().items() if exe.lower() in targets]


def cursor_pids() -> list[int]:
    return pids_by_name("cursor.exe")


def launched_from_cursor() -> bool:
    table = process_table()
    pid = os.getpid()
    seen: set[int] = set()
    while pid in table and pid not in seen:
        seen.add(pid)
        ppid, name = table[pid]
        if name.lower() == "cursor.exe":
            return True
        pid = ppid
    return False


def relaunch_detached() -> None:
    """Re-run this script in its own console so closing Cursor doesn't kill it."""
    env = dict(os.environ, **{DETACHED_ENV: "1"})
    cmd = [sys.executable, os.path.abspath(__file__), *sys.argv[1:]]
    flags = CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP
    try:
        subprocess.Popen(cmd, env=env, creationflags=flags | CREATE_BREAKAWAY_FROM_JOB, close_fds=True)
    except OSError:
        subprocess.Popen(cmd, env=env, creationflags=flags, close_fds=True)
    log("Started in a separate console window, since Cursor must close during the install.")


def remove_stale_staged_update(install_dir: Path) -> None:
    staged = install_dir / "_"
    if staged.is_dir():
        shutil.rmtree(staged, ignore_errors=True)
        if not staged.exists():
            log("Removed background staged-update folder.")


def close_cursor(install_dir: Path, assume_yes: bool) -> bool:
    if not cursor_pids():
        remove_stale_staged_update(install_dir)
        return True

    if not TASKKILL_EXE.is_file():
        raise RuntimeError(f"taskkill executable not found at {TASKKILL_EXE}")

    if not assume_yes:
        answer = input("Cursor is running and must be closed. Close it now? [y/N] ")
        if answer.strip().lower() not in ("y", "yes"):
            return False

    # Clear staged background updates first so Cursor doesn't spawn inno_updater.exe on exit.
    remove_stale_staged_update(install_dir)

    log("Asking Cursor to close (save any unsaved files if prompted)...")
    subprocess.run([str(TASKKILL_EXE), "/IM", "Cursor.exe"], capture_output=True, close_fds=True)
    for _ in range(120):  # Wait up to 60 seconds for graceful exit / save prompts.
        time.sleep(0.5)
        if not cursor_pids():
            break
    else:
        if not assume_yes:
            force_ans = input(
                "Cursor is still open (check for unsaved work). Force-close it now? [y/N] "
            )
            if force_ans.strip().lower() not in ("y", "yes"):
                return False
        log("Force-closing Cursor...")
        subprocess.run(
            [str(TASKKILL_EXE), "/IM", "Cursor.exe", "/F", "/T"],
            capture_output=True,
            close_fds=True,
        )

    for _ in range(30):
        if not pids_by_name("cursor.exe", "inno_updater.exe"):
            # Give helper processes and file handles a moment to release.
            time.sleep(2)
            return True
        time.sleep(0.5)

    log("Some Cursor processes are still running. Close them in Task Manager and retry.")
    return False


def run_verified_installer(installer: Path) -> int:
    install_log = DOWNLOAD_DIR / f"install-{time.strftime('%Y%m%d-%H%M%S')}.log"
    args = [
        str(installer),
        "/SILENT",
        "/SP-",
        "/SUPPRESSMSGBOXES",
        "/NORESTART",
        "/CLOSEAPPLICATIONS",
        f"/LOG={install_log}",
    ]
    with read_lock(installer):
        if not signature_ok(installer):
            raise RuntimeError(f"Refusing to execute unverified installer: {installer}")
        log(f"Running verified installer (log: {install_log})")
        return subprocess.run(args, close_fds=True).returncode


def launch_cursor(install_dir: Path) -> None:
    exe = install_dir / "Cursor.exe"
    if exe.is_file() and not cursor_pids():
        subprocess.Popen(
            [str(exe)],
            creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )
        log("Launched Cursor.")


def cleanup_old_installers(keep: Path) -> None:
    for pattern in ("CursorUserSetup-*.exe", "CursorSetup-*.exe"):
        for old in DOWNLOAD_DIR.glob(pattern):
            if old != keep:
                old.unlink(missing_ok=True)


def pause_if_detached() -> None:
    if os.environ.get(DETACHED_ENV):
        try:
            input("Press Enter to close this window...")
        except EOFError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Download and install the latest stable Cursor release."
    )
    parser.add_argument("--force", action="store_true", help="Install even if already up to date.")
    parser.add_argument(
        "--download-only", action="store_true", help="Download and verify, but don't install."
    )
    parser.add_argument("--yes", "-y", action="store_true", help="Close Cursor without asking.")
    parser.add_argument(
        "--no-launch", action="store_true", help="Don't start Cursor after installing."
    )
    args = parser.parse_args()

    if sys.platform != "win32":
        log("This script only supports Windows.")
        return 1

    install_dir, platform_str = detect_install()
    latest = fetch_latest_stable(platform_str)
    current = installed_version(install_dir)
    log(
        f"Installed ({platform_str}): {current or 'not found'}   "
        f"Latest stable: {latest['version']}"
    )

    if current and not args.force and parse_version(current) >= parse_version(latest["version"]):
        log("Cursor is already up to date.")
        return 0

    if not args.download_only and not os.environ.get(DETACHED_ENV) and launched_from_cursor():
        relaunch_detached()
        return 0

    installer = DOWNLOAD_DIR / safe_installer_name(latest["downloadUrl"], latest["version"])
    if installer.is_file() and signature_ok(installer):
        log(f"Using previously downloaded {installer.name}")
    else:
        log(f"Downloading {installer.name}")
        download(latest["downloadUrl"], installer)
        if not signature_ok(installer):
            installer.unlink(missing_ok=True)
            return 1
    log("Installer signature verified.")

    if args.download_only:
        log(f"Installer saved to {installer}")
        return 0

    if not close_cursor(install_dir, args.yes):
        log("Update cancelled.")
        return 1

    code = run_verified_installer(installer)
    if code != 0:
        log(f"Installer failed with exit code {code}. Check the install log above.")
        return code

    new_version = installed_version(install_dir)
    if new_version and parse_version(new_version) >= parse_version(latest["version"]):
        log(f"Cursor updated to {new_version}.")
        remove_stale_staged_update(install_dir)
        cleanup_old_installers(installer)
    else:
        log(f"Installer finished, but installed version is {new_version!r}.")

    if not args.no_launch:
        launch_cursor(install_dir)
    return 0


if __name__ == "__main__":
    try:
        rc = main()
    except KeyboardInterrupt:
        rc = 130
    except Exception as exc:
        log(f"Error: {exc}")
        rc = 1
    pause_if_detached()
    sys.exit(rc)
