# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
Common helpers
"""

from   __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from   datetime   import datetime, timezone
from   pathlib    import Path
from   typing     import Iterable, Optional

VERSION                   = "1.1.0"
FREEBSD_INSTALLED_CONFIG  = Path("/usr/local/etc/ezfs2fa.json")
LINUX_INSTALLED_CONFIG    = Path("/etc/ezfs2fa.json")
WINDOWS_INSTALLED_CONFIG  = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ezfs2fa" / "ezfs2fa.json"
ZFS_RAW_KEY_BYTES         = 32
WRAP_VERSION              = "ezfs2fa-wrap-v3.0.1"
INSTALLED_SCRIPT_DIRS     = {
    Path("/usr/local/libexec/ezfs2fa"),
    Path("/usr/local/share/ezfs2fa"),
}

# ------------------------------------------------------------------------------
class Error(RuntimeError):
    """User-facing error"""
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
class RelaunchRequested(RuntimeError):
    """Raised when the process intentionally relaunches itself with elevation"""
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def now_utc() -> str:
    """Return an ISO-8601 UTC timestamp"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def eprint(message: str) -> None:
    """Print a message to stderr"""
    print(message, file=sys.stderr)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def require_root() -> None:
    """Require root privileges"""
    os_name = current_os()
    if os_name == "Windows":
        if _is_windows_admin(): return
        _relaunch_windows_as_admin()
        raise RelaunchRequested("requested Administrator elevation")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return
    raise Error("this command must run as root")
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def require_commands(names: Iterable[str]) -> None:
    """Require external commands to exist"""
    for name in names:
        if shutil.which(name) is None:
            raise Error(f"missing command: {name}")
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def run(args: list[str], *, input_bytes: Optional[bytes] = None, capture: bool = False, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    """Run an external command"""
    stdout = subprocess.PIPE if capture else None
    stderr = subprocess.PIPE if capture else None
    proc   = subprocess.run(args, input=input_bytes, stdout=stdout, stderr=stderr)
    if check and proc.returncode != 0:
        if capture and proc.stderr:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            raise Error(f"command failed: {' '.join(args)}\n{detail}")
        raise Error(f"command failed: {' '.join(args)}")
    return proc
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def safe_name(value: str) -> str:
    """Return a conservative name for labels and paths"""
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
    cleaned = "".join(ch for ch in value if ch in allowed)
    if cleaned:
        return cleaned
    raise Error(f"invalid name: {value!r} contains no safe characters")
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def installed_config_path() -> Path:
    """Return the OS-specific installed config path"""
    os_name = current_os()
    if   os_name == "FreeBSD": return FREEBSD_INSTALLED_CONFIG
    if   os_name == "Linux":   return LINUX_INSTALLED_CONFIG
    if   os_name == "Windows": return WINDOWS_INSTALLED_CONFIG
    return LINUX_INSTALLED_CONFIG
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def current_os() -> str:
    """Return normalized OS name"""
    return platform.system() or sys.platform
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _is_windows_admin() -> bool:
    """Return True when running as an elevated Administrator token on Windows"""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as exc:
        raise Error(f"cannot determine Administrator privileges on Windows: {exc}") from exc
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _relaunch_windows_as_admin() -> None:
    """Relaunch the current command under UAC elevation on Windows"""
    try:
        import ctypes
    except Exception as exc:
        raise Error(f"cannot request Administrator elevation on Windows: {exc}") from exc
    script_or_exe = Path(sys.argv[0]).resolve()
    if script_or_exe.suffix.lower() in {".py", ".pyw"}:
        lp_file       = sys.executable
        lp_parameters = subprocess.list2cmdline([str(script_or_exe), *sys.argv[1:]])
    else:
        lp_file       = str(script_or_exe)
        lp_parameters = subprocess.list2cmdline(sys.argv[1:])
    code = ctypes.windll.shell32.ShellExecuteW(None, "runas", lp_file, lp_parameters, None, 1)
    if code <= 32:
        raise Error(f"Administrator elevation request failed or was cancelled (ShellExecuteW code {code})")
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def default_config_path(script_file: str) -> Path:
    """Return installed or standalone default config path.
    Installed mode uses an OS-specific system config path:
        FreeBSD: /usr/local/etc/ezfs2fa.json
        Linux:   /etc/ezfs2fa.json
        Windows: %ProgramData%/ezfs2fa/ezfs2fa.json
    Standalone mode uses ezfs2fa.json next to ezfs2fa.py.
    """
    script_dir = Path(script_file).resolve().parent
    if   script_dir in INSTALLED_SCRIPT_DIRS: return installed_config_path()
    return script_dir / "ezfs2fa.json"
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def chmod_private(path: Path) -> None:
    """Set a path to 0600 where possible"""
    try:
        os.chmod(path, 0o600)
    except OSError as exc:
        eprint(f"WARNING: failed to set 0600 on {path}: {exc}")
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def prompt_confirm(prompt: str, *, default: bool = False) -> bool:
    """Prompt for yes/no confirmation"""
    suffix = "[Y/n]" if default else "[y/N]"
    answer = input(f"{prompt} {suffix}: ").strip().lower()
    if   not answer: return default
    return answer in {"y", "yes"}
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def prompt_value(prompt: str, default: str = "") -> str:
    """Prompt for a value with optional default"""
    suffix = f" [{default}]" if default else ""
    value  = input(f"{prompt}{suffix}: ").strip()
    return value or default
# ------------------------------------------------------------------------------
