# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
OpenZFS subprocess operations
"""

from   __future__ import annotations

import getpass
import subprocess
import sys
import time
from   datetime   import datetime, timezone
from   pathlib    import Path
from   typing     import Dict, List, Optional

from   .common    import Error, require_commands, run

HEX_KEY_BYTES   = 32
HEX_KEY_CHARS   = HEX_KEY_BYTES * 2


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
def _file_uri(path: Path) -> str:
    """Return absolute file:// URI for a local path"""
    return path.resolve().as_uri()
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def _normalize_hex_key(key_hex: str) -> str:
    """Normalize and validate a 64-hex-character ZFS key"""
    cleaned = "".join(ch for ch in key_hex.strip() if not ch.isspace())
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != HEX_KEY_CHARS:
        raise Error(f"hex key must be exactly {HEX_KEY_CHARS} hex characters ({HEX_KEY_BYTES} bytes)")
    try:
        key_bytes = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise Error(f"hex key contains invalid characters: {exc}") from exc
    if len(key_bytes) != HEX_KEY_BYTES:
        raise Error(f"hex key must decode to exactly {HEX_KEY_BYTES} bytes")
    return key_bytes.hex()
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def prompt_hex_key(dataset: str) -> bytearray:
    """
    Prompt for a 32-byte hex key and return it as mutable bytes.
    The key is requested twice and must match.
    """
    first             = getpass.getpass(f"Hex key for {dataset} (64 hex characters): ")
    second            = getpass.getpass(f"Confirm hex key for {dataset}: ")
    first_normalized  = _normalize_hex_key(first)
    second_normalized = _normalize_hex_key(second)
    if first_normalized != second_normalized:
        raise Error("hex key confirmation mismatch")
    return bytearray(bytes.fromhex(first_normalized))
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def _hex_key_input_bytes(key_hex: str) -> bytes:
    """Return normalized key material for stdin prompt loading"""
    normalized = _normalize_hex_key(key_hex)
    return (normalized + "\n").encode("ascii")
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
def _command_text(proc: subprocess.CompletedProcess[bytes]) -> str:
    """Return stdout+stderr decoded into one trimmed diagnostic block"""
    stdout = _decode_output(proc.stdout or b"")
    stderr = _decode_output(proc.stderr or b"")
    return "\n".join(part for part in [stdout, stderr] if part).strip()
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def _parse_pool_names(text: str) -> List[str]:
    """Parse `pool: <name>` lines from zpool output into a unique name list"""
    pools: List[str] = []
    seen             = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("pool:"): continue
        name = line.split(":", 1)[1].strip()
        if not name or name in seen: continue
        pools.append(name)
        seen.add(name)
    return pools
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def _parse_zfs_mount_rows(text: str) -> List[Dict[str, str]]:
    """Parse `zfs mount` output rows as dataset/mountpoint dictionaries"""
    rows: List[Dict[str, str]] = []
    for raw_line in text.splitlines():
        line  = raw_line.strip()
        if not line: continue
        parts = line.split()
        if len(parts) < 2: continue
        if parts[0].upper() == "NAME" and parts[1].upper() == "MOUNTPOINT":
            continue
        dataset    = parts[0]
        mountpoint = " ".join(parts[1:])
        rows.append({
            "dataset":    dataset,
            "mountpoint": mountpoint,
        })
    return rows
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def scan_pool_inventory() -> Dict[str, List[Dict[str, str]]]:
    """
    Scan imported/importable pools using:
      - zpool status
      - zpool import
      - zfs mount
    Returns deduplicated imported/importable name lists.
    """
    require_commands(["zpool", "zfs"])
    status_proc      = run(["zpool", "status"], capture=True, check=False)
    import_proc      = run(["zpool", "import"], capture=True, check=False)
    mount_proc       = run(["zfs", "mount"],   capture=True, check=False)
    status_text      = _command_text(status_proc)
    import_text      = _command_text(import_proc)
    mount_text       = _command_text(mount_proc)
    imported_names   = _parse_pool_names(status_text)
    importable_names = _parse_pool_names(import_text)
    if status_proc.returncode != 0 and not imported_names:
        lower = status_text.lower()
        if "no pools available" not in lower:
            raise Error(f"command failed: zpool status\n{status_text or f'exit status {status_proc.returncode}'}")
    if import_proc.returncode != 0 and not importable_names:
        lower = import_text.lower()
        if "no pools available to import" not in lower:
            raise Error(f"command failed: zpool import\n{import_text or f'exit status {import_proc.returncode}'}")
    if mount_proc.returncode != 0:
        lower = mount_text.lower()
        if "no datasets available" not in lower:
            raise Error(f"command failed: zfs mount\n{mount_text or f'exit status {mount_proc.returncode}'}")
        mounted_rows: List[Dict[str, str]] = []
    else:
        mounted_rows = _parse_zfs_mount_rows(mount_text)
    for row in mounted_rows:
        dataset  = row.get("dataset", "")
        pool     = dataset.split("/", 1)[0].strip()
        if not pool or pool in imported_names: continue
        imported_names.append(pool)
    imported     = [{"name": name} for name in imported_names]
    imported_set = {pool["name"] for pool in imported}
    importable   = [{"name": name} for name in importable_names if name not in imported_set]
    return {
        "imported":   imported,
        "importable": importable,
    }
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def _run_zpool_command(args: List[str]) -> subprocess.CompletedProcess[bytes]:
    """Run a zpool command and return captured process output"""
    require_commands(["zpool"])
    return run(args, capture=True, check=False)
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def _raise_if_command_failed(args: List[str], proc: subprocess.CompletedProcess[bytes]) -> None:
    """Raise a project Error with merged stdout/stderr when command fails"""
    if proc.returncode == 0: return
    detail = _command_text(proc)
    raise Error(f"command failed: {' '.join(args)}\n{detail or f'exit status {proc.returncode}'}")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def import_zpool(pool_name: str, *, force: bool = False) -> None:
    """Import one zpool; use force to run `zpool import -f`"""
    args = ["zpool", "import"]
    if force:
        args.append("-f")
    args.append(pool_name)
    proc = _run_zpool_command(args)
    _raise_if_command_failed(args, proc)
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def export_zpool(pool_name: str, *, force: bool = False) -> None:
    """Export one zpool; use force to run `zpool export -f`"""
    args = ["zpool", "export"]
    if force:
        args.append("-f")
    args.append(pool_name)
    proc = _run_zpool_command(args)
    _raise_if_command_failed(args, proc)
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def import_failure_suggests_force(message: str) -> bool:
    """Return True when import failure text suggests retrying with `zpool import -f`"""
    lower = message.lower()
    if "-f" not in lower: return False
    hints = [
        "previously in use from another system",
        "may be in use from other system",
        "last accessed by",
        "use 'zpool import -f'",
        "use '-f' to import",
    ]
    return any(hint in lower for hint in hints)
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
        "-o",  f"keylocation={_file_uri(key_path)}",
        "-o",  f"canmount={canmount}",
        "-o",  f"mountpoint={mountpoint}",
        dataset,
    ], capture=True)
    run(["zfs", "set", "keylocation=prompt", dataset], capture=True)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def create_dataset_hex(dataset: str, mountpoint: str, canmount: str, key_hex: str) -> None:
    """Create encrypted dataset with keyformat=hex and keylocation=prompt"""
    require_commands(["zfs"])
    run([
        "zfs", "create",
        "-o",  "encryption=on",
        "-o",  "keyformat=hex",
        "-o",  "keylocation=prompt",
        "-o",  f"canmount={canmount}",
        "-o",  f"mountpoint={mountpoint}",
        dataset,
    ], input_bytes=_hex_key_input_bytes(key_hex), capture=True)
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
    args.extend(["-L", _file_uri(key_path), dataset])
    run(args, capture=True)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def load_key_hex(dataset: str, key_hex: str, *, dry_run: bool = False) -> None:
    """Load ZFS key using keyformat=hex through stdin prompt"""
    require_commands(["zfs"])
    args = ["zfs", "load-key"]
    if dry_run:
        args.append("-n")
    args.extend(["-L", "prompt", dataset])
    run(args, input_bytes=_hex_key_input_bytes(key_hex), capture=True)
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
        "-o",  f"keylocation={_file_uri(key_path)}",
        dataset,
    ], capture=True)
    run(["zfs", "set", "keylocation=prompt", dataset], capture=True)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def change_key_hex(dataset: str, key_hex: str) -> None:
    """Change dataset wrapping key to keyformat=hex with interactive prompt semantics"""
    require_commands(["zfs"])
    run([
        "zfs", "change-key",
        "-o",  "keyformat=hex",
        "-o",  "keylocation=prompt",
        dataset,
    ], input_bytes=_hex_key_input_bytes(key_hex), capture=True)
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
