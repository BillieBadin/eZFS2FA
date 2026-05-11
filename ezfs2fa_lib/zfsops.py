# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
OpenZFS subprocess operations
"""

from   __future__ import annotations

from   datetime import datetime, timezone
from   pathlib import Path
from   typing import Optional

from   .common import Error, require_commands, run

# ------------------------------------------------------------------------------
def zfs_get(dataset: str, prop: str) -> str:
    """Read one ZFS property"""
    require_commands(["zfs"])
    proc = run(["zfs", "get", "-H", "-o", "value", prop, dataset], capture=True)
    return proc.stdout.decode("utf-8", "replace").strip()
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def create_dataset(dataset: str, mountpoint: str, canmount: str, key_path: Path) -> None:
    """Create encrypted dataset with raw key file"""
    require_commands(["zfs"])
    if key_path.stat().st_size != 32:
        raise Error(f"key file must be 32 bytes: {key_path}")
    run([
        "zfs", "create",
        "-o",  "encryption=on",
        "-o",  "keyformat=raw",
        "-o",  f"keylocation=file://{key_path}",
        "-o",  f"canmount={canmount}",
        "-o",  f"mountpoint={mountpoint}",
        dataset,
    ], capture=True)
    run(["zfs", "set", "keylocation=prompt", dataset], capture=True)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def load_key(dataset: str, key_path: Path, *, dry_run: bool = False) -> None:
    """Load ZFS key from a regular file"""
    require_commands(["zfs"])
    if key_path.stat().st_size != 32:
        raise Error(f"key file must be 32 bytes: {key_path}")
    args = ["zfs", "load-key"]
    if dry_run:
        args.append("-n")
    args.extend(["-L", f"file://{key_path}", dataset])
    run(args, capture=True)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def change_key(dataset: str, key_path: Path) -> None:
    """Change dataset wrapping key to a new raw key file"""
    require_commands(["zfs"])
    if key_path.stat().st_size != 32:
        raise Error(f"key file must be 32 bytes: {key_path}")
    run([
        "zfs", "change-key",
        "-o",  "keyformat=raw",
        "-o",  f"keylocation=file://{key_path}",
        dataset,
    ], capture=True)
    run(["zfs", "set", "keylocation=prompt", dataset], capture=True)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def mount_dataset(dataset: str) -> None:
    """Mount dataset if needed"""
    if zfs_get(dataset, "mounted") != "yes":
        run(["zfs", "mount", dataset], capture=True)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def unload_key(dataset: str) -> None:
    """Unload dataset key if loaded"""
    if zfs_get(dataset, "keystatus") == "available":
        run(["zfs", "unload-key", dataset], capture=True)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def unmount_dataset(dataset: str, *, force_delay: Optional[int] = None) -> None:
    """Unmount dataset, optionally forcing after a delay"""
    import subprocess
    import sys
    import time
    if   zfs_get(dataset, "mounted") != "yes": return
    proc = subprocess.run(["zfs", "unmount", dataset])
    if   proc.returncode == 0: return
    if force_delay is None:
        raise Error("normal unmount failed; stop dependent services or use -F seconds")
    print(f"Normal unmount failed. Waiting {force_delay} seconds before forced unmount.", file=sys.stderr)
    time.sleep(force_delay)
    run(["zfs", "unmount", "-f", dataset], capture=True)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def default_snapshot_name() -> str:
    """Return lock-time snapshot suffix"""
    return "locked-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def resolve_snapshot_name(dataset: str, requested: Optional[str]) -> str:
    """Resolve requested snapshot name"""
    suffix = requested or default_snapshot_name()
    if "@" in suffix:
        snap_dataset, snap_name = suffix.split("@", 1)
        if snap_dataset != dataset:
            raise Error(f"snapshot dataset mismatch: expected {dataset}, got {snap_dataset}")
    else:
        snap_name = suffix
    if not snap_name or any(ch in set(" /\t\n\r") for ch in snap_name):
        raise Error(f"unsafe snapshot name: {snap_name}")
    return f"{dataset}@{snap_name}"
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def snapshot_dataset(dataset: str, requested: Optional[str]) -> str:
    """Create snapshot and return name"""
    snapshot = resolve_snapshot_name(dataset, requested)
    run(["zfs", "snapshot", snapshot], capture=True)
    return snapshot
# ------------------------------------------------------------------------------
