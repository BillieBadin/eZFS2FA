# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
OpenZFS subprocess operations
"""

from   __future__ import annotations

import subprocess
import sys
import time
from   datetime   import datetime, timezone
from   pathlib    import Path
from   typing     import Dict, List, Optional

from   .common    import Error, require_commands, run


# ------------------------------------------------------------------------------
def _decode_output(data: bytes) -> str:
    """Decode subprocess output as UTF-8 with replacement"""
    return data.decode("utf-8", "replace")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def _split_fields(line: str, expected: int, *, command: str) -> List[str]:
    """Split one -H output line into exactly expected tab-delimited fields"""
    fields = line.rstrip("\n").split("\t")
    if len(fields) != expected:
        raise Error(f"unexpected output from {command}: {line}")
    return fields
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def list_imported_zpools() -> List[Dict[str, str]]:
    """Return imported zpools with capacity and health details"""
    require_commands(["zpool"])
    proc   = run(["zpool", "list", "-Hp", "-o", "name,size,alloc,free,health"], capture=True, check=False)
    stdout = _decode_output(proc.stdout).strip()
    stderr = _decode_output(proc.stderr).strip()
    if proc.returncode != 0:
        detail = "\n".join(part for part in [stderr, stdout] if part)
        lower  = detail.lower()
        if "no pools available" in lower: return []
        raise Error(f"command failed: zpool list -Hp -o name,size,alloc,free,health\n{detail or f'exit status {proc.returncode}'}")
    if not stdout: return []
    pools: List[Dict[str, str]] = []
    for line in stdout.splitlines():
        if not line.strip(): continue
        name, size, alloc, free, health = _split_fields(line, 5, command="zpool list")
        pools.append({
            "name":   name,
            "size":   size,
            "alloc":  alloc,
            "free":   free,
            "health": health,
        })
    return pools
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def list_importable_zpools() -> List[Dict[str, str]]:
    """Return zpools visible to `zpool import`"""
    require_commands(["zpool"])
    proc   = run(["zpool", "import"], capture=True, check=False)
    stdout = _decode_output(proc.stdout)
    stderr = _decode_output(proc.stderr)
    text   = "\n".join(part for part in [stdout, stderr] if part).strip()
    pools: List[Dict[str, str]] = []
    seen   = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("pool:"): continue
        name = line.split(":", 1)[1].strip()
        if not name or name in seen: continue
        pools.append({"name": name})
        seen.add(name)
    if proc.returncode != 0 and not pools:
        lower = text.lower()
        if "no pools available to import" in lower: return []
        raise Error(f"command failed: zpool import\n{text or f'exit status {proc.returncode}'}")
    return pools
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def list_zpools() -> Dict[str, List[Dict[str, str]]]:
    """Return imported and importable zpool inventories"""
    return {
        "imported":   list_imported_zpools(),
        "importable": list_importable_zpools(),
    }
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def list_datasets() -> List[Dict[str, str]]:
    """Return all filesystem and volume datasets with key properties"""
    require_commands(["zfs"])
    proc = run([
        "zfs", "list",
        "-H",
        "-o", "name,type,encryption,keystatus,mounted,mountpoint,volsize",
        "-t", "filesystem,volume",
    ], capture=True, check=False)
    stdout = _decode_output(proc.stdout).strip()
    stderr = _decode_output(proc.stderr).strip()
    if proc.returncode != 0:
        detail = "\n".join(part for part in [stderr, stdout] if part)
        lower  = detail.lower()
        if "no datasets available" in lower: return []
        raise Error(f"command failed: zfs list -H -o name,type,encryption,keystatus,mounted,mountpoint,volsize -t filesystem,volume\n{detail or f'exit status {proc.returncode}'}")
    if not stdout: return []
    datasets: List[Dict[str, str]] = []
    for line in stdout.splitlines():
        if not line.strip(): continue
        name, ds_type, encryption, keystatus, mounted, mountpoint, volsize = _split_fields(line, 7, command="zfs list")
        datasets.append({
            "name":       name,
            "type":       ds_type,
            "encryption": encryption,
            "keystatus":  keystatus,
            "mounted":    mounted,
            "mountpoint": mountpoint,
            "volsize":    volsize,
        })
    return datasets
# ------------------------------------------------------------------------------

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
def ensure_keylocation_prompt(dataset: str) -> None:
    """Force keylocation=prompt when dataset holds a stale file:// path"""
    require_commands(["zfs"])
    current = zfs_get(dataset, "keylocation")
    if current in {"prompt", "-", "none"}: return
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
