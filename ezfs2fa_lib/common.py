# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
Common helpers
"""

from   __future__ import annotations

import os
import shutil
import subprocess
import sys
from   datetime import datetime, timezone
from   pathlib import Path
from   typing import Iterable, Optional

VERSION                   = "1.0.0"
FREEBSD_INSTALLED_CONFIG  = Path("/usr/local/etc/ezfs2fa.json")
LINUX_INSTALLED_CONFIG    = Path("/etc/ezfs2fa.json")
ZFS_RAW_KEY_BYTES         = 32
WRAP_VERSION              = "ezfs2fa-wrap-v3.0.0"
INSTALLED_SCRIPT_DIRS     = {
    Path("/usr/local/libexec/ezfs2fa"),
    Path("/usr/local/share/ezfs2fa"),
}

# ------------------------------------------------------------------------------
class Error(RuntimeError):
    """User-facing error"""
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
    if os.geteuid() != 0:
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
    return cleaned or "item"
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def installed_config_path() -> Path:
    """Return the OS-specific installed config path"""
    if   sys.platform.startswith("freebsd"): return FREEBSD_INSTALLED_CONFIG
    if   sys.platform.startswith("linux"): return LINUX_INSTALLED_CONFIG
    return LINUX_INSTALLED_CONFIG
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def default_config_path(script_file: str) -> Path:
    """Return installed or standalone default config path.
    Installed mode uses an OS-specific system config path:
        FreeBSD: /usr/local/etc/ezfs2fa.json
        Linux:   /etc/ezfs2fa.json
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
    except PermissionError as exc:
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
