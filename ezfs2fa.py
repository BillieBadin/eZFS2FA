#!/usr/bin/env python3
# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
ezfs2fa: OpenZFS dataset unlock with passphrase and/or FIDO2
"""

# Standard libraries
from   __future__          import annotations

import argparse
import hashlib
import os
import secrets
import shutil
import sys
import tarfile
import uuid
from   pathlib             import Path
from   typing              import Any, Dict, List, Optional, Set

# eZFS2FA+ libraries
from   ezfs2fa_lib.common  import (
    VERSION, ZFS_RAW_KEY_BYTES,
    Error, RelaunchRequested,
    chmod_private, current_os,
    default_config_path,
    eprint, now_utc, safe_name,
    prompt_confirm, prompt_value,
    require_commands, require_root,
)
from   ezfs2fa_lib.config  import dataset_entry, ensure_config, resolve_dataset, save_config
from   ezfs2fa_lib.crypto  import wipe_buffer
from   ezfs2fa_lib.fido    import FidoManager
from   ezfs2fa_lib.key_wrap import wrap_key_record, unwrap_key_record
from   ezfs2fa_lib.scratch import ScratchSpace
from   ezfs2fa_lib.wrapper_upgrade import cmd_upgrade_wrappers
from   ezfs2fa_lib         import zfsops


DEFAULT_CONFIG = str(default_config_path(__file__))


# ------------------------------------------------------------------------------
def resolve_auth_flags(
    args:   argparse.Namespace,
    *,
    prompt: bool) -> tuple[bool, bool]:
    """Resolve passphrase/FIDO2 auth flags"""
    use_passphrase = bool(getattr(args, "passphrase", False))
    use_fido       = bool(getattr(args, "fido", False))
    if not use_passphrase and not use_fido and prompt:
        use_passphrase = prompt_confirm("Protect this wrapper with a passphrase", default=True)
        use_fido       = prompt_confirm("Protect this wrapper with a FIDO2/YubiKey", default=True)
    if not use_passphrase and not use_fido:
        raise Error("at least one factor is required: --passphrase/--pass or --fido")
    return use_passphrase, use_fido
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def ensure_fido_backend_available(
    cfg:      Dict[str, Any],
    *,
    use_fido: bool
) -> None:
    """Fail early with an actionable message when FIDO is requested but unavailable"""
    if not use_fido: return
    manager = FidoManager(cfg)
    if manager.backend.available(): return
    raise Error(
        "FIDO2 wrapper requested, but no usable backend is available. "
        f"{manager.unavailable_message()} "
        "Alternatively, use --passphrase without --fido."
    )
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def choose_wrapper(
    entry: Dict[str, Any],
    name:  Optional[str]
) -> tuple[str, Dict[str, Any]]:
    """Select wrapper by name or interactively"""
    wrappers = entry.get("wrappers", {})
    if not wrappers:
        raise Error("no wrappers enrolled for this dataset")
    if name:
        if name not in wrappers:
            raise Error(f"wrapper not found: {name}")
        return name, wrappers[name]
    names = sorted(wrappers)
    if   len(names) == 1: return names[0], wrappers[names[0]]
    print("Available wrappers:")
    for item in names:
        wrapper = wrappers[item]
        factors = []
        if wrapper.get("passphrase"):
            factors.append("passphrase")
        if wrapper.get("fido2"):
            factors.append("fido2")
        print(f"  {item} ({', '.join(factors)})")
    selected = prompt_value("Wrapper name")
    if selected not in wrappers:
        raise Error(f"wrapper not found: {selected}")
    return selected, wrappers[selected]
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def iter_wrappers(cfg: Dict[str, Any]):
    """Yield every configured wrapper as (dataset, wrapper_name, wrapper)"""
    for dataset, entry in cfg.get("datasets", {}).items():
        for name, wrapper in entry.get("wrappers", {}).items():
            yield dataset, name, wrapper
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def config_has_datasets_or_wrappers(cfg: Dict[str, Any]) -> bool:
    """Return True when config already has enrolled data"""
    return bool(cfg.get("datasets", {}))
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def has_backup_evidence(cfg: Dict[str, Any]) -> bool:
    """Return True when at least one accepted backup proof exists"""
    wrappers = list(iter_wrappers(cfg))
    if   not wrappers: return True
    if all(wrapper.get("last_export_at") for _, _, wrapper in wrappers):
        return True
    evidence = cfg.get("backup_evidence", {})
    return bool(evidence.get("last_pack_at") or evidence.get("last_export_raw_at"))
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def stamp_all_wrappers_export(
    cfg:   Dict[str, Any],
    stamp: str
) -> bool:
    """Set wrapper last_export_at for every wrapper; return True if any wrapper exists"""
    changed = False
    for _, _, wrapper in iter_wrappers(cfg):
        wrapper["last_export_at"] = stamp
        changed = True
    return changed
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def warn_missing_backup_evidence(cfg: Dict[str, Any]) -> None:
    """Warn when no backup evidence exists yet"""
    if   has_backup_evidence(cfg): return
    pending = [f"{dataset}/{name}" for dataset, name, wrapper in iter_wrappers(cfg) if not wrapper.get("last_export_at")]
    if   not pending: return
    eprint("WARNING: no backup evidence recorded yet.")
    eprint("WARNING: run 'ezfs2fa backup -o ...', 'ezfs2fa pack -o ...', 'ezfs2fa export-raw -o ...', or use '--manualbackup'.")
    eprint("WARNING: wrappers pending backup evidence: " + ", ".join(pending))
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def start_pending_op(
    cfg_path:     Path,
    cfg:          Dict[str, Any],
    *, operation: str,
    dataset:      str,
    entry:        Dict[str, Any]
) -> str:
    """Persist a pending operation before a key-changing ZFS action"""
    pending_id = uuid.uuid4().hex
    cfg["pending_op"] = {
        "id":         pending_id,
        "operation":  operation,
        "dataset":    dataset,
        "created_at": now_utc(),
        "entry":      entry,
    }
    save_config(cfg_path, cfg)
    return pending_id
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def clear_pending_op(
    cfg:         Dict[str, Any],
    *,
    expected_id: Optional[str] = None
) -> None:
    """Clear pending operation metadata in-memory"""
    pending = cfg.get("pending_op")
    if   pending is None: return
    if expected_id and pending.get("id") != expected_id:
        raise Error("pending operation mismatch; refusing to clear unexpected pending state")
    cfg["pending_op"] = None
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def warn_pending_op(cfg: Dict[str, Any]) -> None:
    """Warn when previous key-changing operation did not complete config finalization"""
    pending  = cfg.get("pending_op")
    if not pending: return
    op_id    = pending.get("id")
    op_name  = pending.get("operation")
    dataset  = pending.get("dataset")
    created  = pending.get("created_at")
    eprint("WARNING: unresolved pending operation detected.")
    eprint(f"WARNING: id={op_id} operation={op_name} dataset={dataset} started={created}")
    eprint("WARNING: run 'ezfs2fa recover-pending' after validating dataset state.")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def ensure_no_pending_for_mutation(
    cfg: Dict[str, Any],
    cmd: str
) -> None:
    """Fail closed on config mutations while a pending operation exists"""
    if not cfg.get("pending_op"): return
    allowed = {"list", "ls", "doctor", "fido-list", "recover-pending", "backup", "pack"}
    if cmd not in allowed:
        raise Error("pending operation exists; run 'ezfs2fa recover-pending' before this command")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def cancel_pending_op(
    cfg_path: Path,
    cfg:      Dict[str, Any]
) -> bool:
    """Drop pending operation metadata if present; return True when changed"""
    if not cfg.get("pending_op"):
        return False
    clear_pending_op(cfg)
    try:
        save_config(cfg_path, cfg)
    except Exception as exc:
        raise Error(f"failed to clear pending operation: {exc}") from exc
    return True
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def validate_dataset_name(
    dataset:         str,
    *,
    allow_pool_root: bool
) -> None:
    """Validate conservative dataset syntax before invoking ZFS commands"""
    if not dataset:
        raise Error("dataset name is empty")
    if dataset != dataset.strip():
        raise Error(f"dataset has leading/trailing whitespace: {dataset!r}")
    if any(ch.isspace() for ch in dataset):
        raise Error(f"dataset contains whitespace: {dataset!r}")
    if any(ch in {"@", "#"} for ch in dataset):
        raise Error(f"dataset must not include snapshot/bookmark separators: {dataset!r}")
    if dataset.startswith("/") or dataset.endswith("/") or "//" in dataset:
        raise Error(f"invalid dataset path format: {dataset!r}")
    if not allow_pool_root and "/" not in dataset:
        raise Error(f"dataset must include pool and child dataset, for example 'zroot/secure': {dataset!r}")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def dataset_pool_name(dataset: str) -> str:
    """Return the pool component from a dataset path"""
    return dataset.split("/", 1)[0]
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def list_pool_names(zpools: Dict[str, List[Dict[str, str]]]) -> Set[str]:
    """Collect every known pool name from imported/importable inventories"""
    names: Set[str] = set()
    for pool in zpools.get("imported", []):
        name = pool.get("name")
        if name:
            names.add(name)
    for pool in zpools.get("importable", []):
        name = pool.get("name")
        if name:
            names.add(name)
    return names
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def imported_pool_names(zpools: Dict[str, List[Dict[str, str]]]) -> Set[str]:
    """Collect currently imported pool names"""
    return {pool["name"] for pool in zpools.get("imported", []) if pool.get("name")}
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def importable_pool_names(zpools: Dict[str, List[Dict[str, str]]]) -> Set[str]:
    """Collect pools visible to zpool import"""
    return {pool["name"] for pool in zpools.get("importable", []) if pool.get("name")}
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def suggest_dataset_default(
    zpools:     Dict[str, List[Dict[str, str]]],
    live_items: List[Dict[str, str]],
    fallback:   str = "zroot/secure"
) -> str:
    """Choose a non-conflicting dataset prompt default from current pools"""
    existing  = {item["name"] for item in live_items if item.get("name")}
    pools     = sorted(imported_pool_names(zpools))
    if not pools:
        pools = sorted(importable_pool_names(zpools))
    if pools:
        base  = f"{pools[0]}/secure"
    else:
        base  = fallback
    if base not in existing: return base
    suffix    = 2
    while f"{base}{suffix}" in existing:
        suffix += 1
    return f"{base}{suffix}"
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def print_zpool_inventory(zpools: Dict[str, List[Dict[str, str]]]) -> None:
    """Print imported and importable zpool inventories"""
    imported = zpools.get("imported", [])
    print(f"Imported zpools: {len(imported)}")
    if imported:
        for pool in imported:
            print(f"    {pool.get('name', '?')} health={pool.get('health', '?')} size={pool.get('size', '?')} alloc={pool.get('alloc', '?')} free={pool.get('free', '?')}")
    else:
        print("    none")
    importable_names = sorted(pool["name"] for pool in zpools.get("importable", []) if pool.get("name"))
    print("Importable zpools: " + (", ".join(importable_names) if importable_names else "none"))
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def cmd_init(args: argparse.Namespace) -> None:
    """Create JSON config"""
    path = Path(args.c)
    cfg  = ensure_config(path)
    if config_has_datasets_or_wrappers(cfg):
        raise Error("refusing to reinitialize: config already has datasets/wrappers; back it up and edit manually")
    save_config(path, cfg)
    print(path)
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def cmd_list(args: argparse.Namespace) -> None:
    """List configured datasets and wrappers"""
    cfg      = ensure_config(Path(args.c))
    try:
        print_zpool_inventory(zfsops.list_zpools())
    except Exception as exc:
        print(f"Zpool inventory: unavailable: {exc}")
    print("")
    datasets = cfg.get("datasets", {})
    if args.d:
        datasets = {args.d: dataset_entry(cfg, args.d)}
    if not datasets:
        print("No datasets configured.")
        return
    for dataset, entry in sorted(datasets.items()):
        print(dataset)
        print(f"    mountpoint: {entry.get('mountpoint', '')}")
        print(f"    rp_id:      {entry.get('rp_id', '')}")
        print(f"    canmount:   {entry.get('canmount', '')}")
        print(f"    keyformat:  {entry.get('keyformat', 'raw')}")
        print(f"    created:    {entry.get('created_at', '')}")
        wrappers = entry.get("wrappers", {})
        if not wrappers:
            print("    enrolled keys: none")
            continue
        print("    enrolled keys:")
        for name, wrapper in sorted(wrappers.items()):
            factors = []
            if wrapper.get("passphrase"):
                factors.append("passphrase")
            if wrapper.get("fido2"):
                factors.append("fido2")
            print(f"        {name}")
            print(f"            factors: {', '.join(factors)}")
            print(f"            created: {wrapper.get('created_at', '')}")
            print(f"            backup:  {wrapper.get('last_export_at') or 'missing'}")
            device = wrapper.get("device", {})
            if device:
                print(f"            serial:  {device.get('serial')}")
                print(f"            device:  {device.get('label') or device.get('path_at_enrolment')}")
                print(f"            backend: {wrapper.get('backend_used') or wrapper.get('backend')}")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def cmd_doctor(args: argparse.Namespace) -> None:
    """Print installation and runtime diagnostics"""
    cfg_path = Path(args.c)
    os_name  = current_os()
    manager  = FidoManager({})
    cli_tools = ["fido2-token", "fido2-cred", "fido2-assert"]
    if   os_name == "FreeBSD":
        scratch_backend = "mdmfs -M"
        base_required   = ["zfs", "zpool", "mdmfs", "mdconfig", "mount", "umount"]
    elif os_name == "Linux":
        scratch_backend = "ramfs"
        base_required   = ["zfs", "zpool", "mount", "umount"]
    elif os_name == "Windows":
        scratch_backend = "temporary private directory (compatibility mode)"
        base_required   = ["zfs", "zpool"]
    else:
        scratch_backend = "temporary private directory (compatibility mode)"
        base_required   = ["zfs", "zpool"]
    required = list(base_required)
    optional: List[str] = []
    if os_name in {"FreeBSD", "Linux"}:
        if getattr(manager.backend, "name", "") == "cli":
            required.extend(cli_tools)
        else:
            optional = list(cli_tools)
    print(f"ezfs2fa:        {VERSION}")
    print(f"OS:            {os_name}")
    print(f"Config:        {cfg_path}")
    print(f"Scratch:       {scratch_backend}")
    print(f"FIDO backend:  {getattr(manager.backend, 'name', 'unknown')}")
    try:
        import cryptography  # noqa: F401
        print("Crypto:        python-cryptography available")
    except ImportError:
        print("Crypto:        python-cryptography MISSING")
    try:
        import fido2  # noqa: F401
        print("FIDO python:   fido2 available")
    except ImportError:
        print("FIDO python:   fido2 MISSING")
    if not manager.backend.available():
        print(f"FIDO status:   unavailable ({manager.unavailable_message()})")
    print("Commands:")
    for name in required:
        path = shutil.which(name)
        print(f"    {name:12} {path if path else 'missing'}")
    if optional:
        print("Optional commands (CLI fallback):")
        for name in optional:
            path = shutil.which(name)
            print(f"    {name:12} {path if path else 'missing'}")
    try:
        print_zpool_inventory(zfsops.list_zpools())
    except Exception as exc:
        print(f"Zpool check:    failed: {exc}")
    try:
        cfg = ensure_config(cfg_path)
        print(f"Datasets:      {len(cfg.get('datasets', {}))}")
    except Exception as exc:
        print(f"Config check:  failed: {exc}")
        return
    try:
        devices = FidoManager(cfg).list_devices()
        print(f"FIDO devices:  {len(devices)}")
        for dev in devices:
            print(f"    {dev.path} responsive={dev.responsive} serial={dev.serial}")
    except Exception as exc:
        print(f"FIDO check:    failed: {exc}")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def cmd_fido_list(args: argparse.Namespace) -> None:
    """List visible FIDO keys using configured backend preference"""
    cfg = ensure_config(Path(args.c))
    manager = FidoManager(cfg)
    backend_name = getattr(manager.backend, "name", "")
    if args.D and backend_name == "cli":
        # Show the explicit path through the CLI backend selection rules. This
        # is useful on FreeBSD where /dev/uhid0 may be a symlink to /dev/u2f/0
        # and may not be returned by automatic discovery while still working
        # perfectly with fido2-cred/fido2-assert.
        from   ezfs2fa_lib.fido_cli import CliFidoBackend
        devices = [CliFidoBackend()._choose(args.D)]
    elif args.D and backend_name == "python-fido2" and current_os() != "Windows":
        devices = manager.list_devices()
        matches = [dev for dev in devices if dev.path == args.D or dev.label == args.D]
        if not matches:
            raise Error(f"FIDO device not found for -D: {args.D}")
        devices = matches
    else:
        if args.D:
            eprint("WARNING: -D is ignored on Windows WebAuthn backend.")
        devices = manager.list_devices()
    for dev in devices:
        print(dev.path)
        print(f"    label:      {dev.label}")
        print(f"    backend:    {dev.backend}")
        print(f"    responsive: {dev.responsive}")
        print(f"    serial:     {dev.serial}")
        print(f"    aaguid:     {dev.aaguid}")
        print(f"    versions:   {', '.join(dev.versions)}")
        print(f"    extensions: {', '.join(dev.extensions)}")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def cmd_mkmd(args: argparse.Namespace) -> None:
    """Create diagnostic scratch filesystem"""
    require_root()
    with ScratchSpace(args.n or "test") as scratch:
        raw_key = bytearray(secrets.token_bytes(ZFS_RAW_KEY_BYTES))
        try:
            scratch.write_key(raw_key)
            print(str(scratch.mountpoint or scratch.path or ""))
            eprint(f"key file: {scratch.key_path()}")
            eprint("Press Enter to destroy scratch filesystem.")
            input()
        finally:
            wipe_buffer(raw_key) # always wipe key from memory no matter what
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def cmd_create(args: argparse.Namespace) -> None:
    """Create encrypted dataset or migrate existing dataset and first wrapper"""
    require_root()
    require_commands(["zfs", "zpool"])
    cfg_path   = Path(args.c)
    cfg        = ensure_config(cfg_path)
    zpools     = zfsops.list_zpools()
    live_items = zfsops.list_datasets()
    dataset    = args.migrate_dataset or args.d or prompt_value("Dataset", suggest_dataset_default(zpools, live_items))
    if args.migrate_dataset and args.d and args.migrate_dataset != args.d:
        raise Error(f"--migrate dataset does not match -d: {args.migrate_dataset} vs {args.d}")
    migrating  = bool(args.migrate_dataset)
    validate_dataset_name(dataset, allow_pool_root=migrating)
    pool_name  = dataset_pool_name(dataset)
    pool_names = list_pool_names(zpools)
    imported   = imported_pool_names(zpools)
    importable = importable_pool_names(zpools)
    if migrating:
        if pool_name not in pool_names:
            available = ", ".join(sorted(pool_names)) if pool_names else "none"
            raise Error(f"zpool not found for dataset '{dataset}': '{pool_name}'. Imported/importable pools: {available}")
    else:
        if pool_name not in imported:
            imported_text = ", ".join(sorted(imported)) if imported else "none"
            importable_text = ", ".join(sorted(importable)) if importable else "none"
            if pool_name in importable:
                raise Error(f"zpool '{pool_name}' is visible but not imported; import it first. Imported pools: {imported_text}. Importable pools: {importable_text}")
            raise Error(f"zpool not imported for dataset '{dataset}': '{pool_name}'. Imported pools: {imported_text}. Importable pools: {importable_text}")
    live_by_name = {item["name"]: item for item in live_items if item.get("name")}
    dataset_live = live_by_name.get(dataset)
    rp_id        = args.r or cfg.get("defaults", {}).get("rp_id", "zfs.local")
    name         = safe_name(args.n or prompt_value("First wrapper name", "primary"))
    use_passphrase, use_fido = resolve_auth_flags(args, prompt=True)
    ensure_fido_backend_available(cfg, use_fido=use_fido)
    if dataset in cfg.setdefault("datasets", {}) and not args.f:
        raise Error(f"dataset already exists in config: {dataset}. Use -f to overwrite config entry.")
    if migrating:
        if not dataset_live:
            raise Error(f"dataset not found on host for migration: {dataset}")
        key_status = dataset_live.get("keystatus", "")
        if key_status != "available":
            raise Error(f"dataset must be unlocked before migration: {dataset}")
        if dataset_live.get("encryption", "") == "off":
            raise Error(f"dataset is not encrypted: {dataset}")
        mountpoint = args.m or dataset_live.get("mountpoint", "") or zfsops.zfs_get(dataset, "mountpoint")
        canmount   = args.C or zfsops.zfs_get(dataset, "canmount")
        eprint(f"About to migrate unlocked encrypted dataset {dataset} into ezfs2fa wrappers and rotate its wrapping key")
    else:
        if dataset_live:
            raise Error(f"dataset already exists on host: {dataset}. Use --migrate to enrol an existing encrypted dataset.")
        mountpoint_default = "/secure"
        if current_os() == "Windows":
            mountpoint_default = f"/{dataset}"
        mountpoint = args.m or prompt_value("Mountpoint", mountpoint_default)
        canmount   = args.C or cfg.get("defaults", {}).get("canmount", "noauto")
        eprint(f"About to create encrypted dataset {dataset} mounted at {mountpoint}")
    if not args.y and not prompt_confirm("Continue"):
        raise Error("cancelled")
    use_hex = bool(args.hex_key)
    if use_hex:
        eprint("Using keyformat=hex with keylocation=prompt. The dataset key is generated randomly and injected automatically.")
    elif current_os() == "Windows":
        eprint("WARNING: raw key mode on Windows uses compatibility scratch files. Prefer --hex when possible.")
    raw_key = bytearray(secrets.token_bytes(ZFS_RAW_KEY_BYTES))
    try:
        entry = {
            "dataset":    dataset,
            "mountpoint": mountpoint,
            "rp_id":      rp_id,
            "canmount":   canmount,
            "keyformat":  "hex" if use_hex else "raw",
            "created_at": now_utc(),
            "wrappers":   {},
        }
        entry["wrappers"][name] = wrap_key_record(raw_key, name=name, rp_id=rp_id, cfg=cfg, use_passphrase=use_passphrase, use_fido=use_fido, fido_device=args.D)
        auto_add = bool(args.a)
        while auto_add or prompt_confirm("Enrol another wrapper now"):
            auto_add = False
            new_name = safe_name(prompt_value("New wrapper name"))
            new_passphrase, new_fido = resolve_auth_flags(args, prompt=True)
            ensure_fido_backend_available(cfg, use_fido=new_fido)
            if new_name in entry["wrappers"]:
                raise Error(f"duplicate wrapper name: {new_name}")
            entry["wrappers"][new_name] = wrap_key_record(raw_key, name=new_name, rp_id=rp_id, cfg=cfg, use_passphrase=new_passphrase, use_fido=new_fido, fido_device=args.D)
        pending_id = start_pending_op(cfg_path, cfg, operation="migrate" if migrating else "create", dataset=dataset, entry=entry)
        if use_hex:
            key_hex = raw_key.hex()
            if migrating:
                zfsops.change_key_hex(dataset, key_hex)
            else:
                zfsops.create_dataset_hex(dataset, mountpoint, canmount, key_hex)
        else:
            with ScratchSpace(safe_name(dataset)) as scratch:
                scratch.write_key(raw_key)
                if migrating:
                    zfsops.change_key(dataset, scratch.key_path())
                else:
                    zfsops.create_dataset(dataset, mountpoint, canmount, scratch.key_path())
        cfg["datasets"][dataset] = entry
        clear_pending_op(cfg, expected_id=pending_id)
        save_config(cfg_path, cfg)
        if not migrating:
            zfsops.mount_dataset(dataset)
    finally:
        wipe_buffer(raw_key) # always wipe key from memory no matter what
    if migrating:
        print(f"Migrated dataset and updated config: {cfg_path}")
    else:
        print(f"Created dataset, mounted it, and updated config: {cfg_path}")
    eprint("IMPORTANT: Back up the JSON config now; there is no recovery path without it.")
    eprint("IMPORTANT: This applies even for passphrase-only wrappers because JSON stores the wrapped raw key context.")
    eprint("IMPORTANT: If you need a zero-dependency recovery path, export a raw key backup to trusted protected offline storage.")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def cmd_unlock(args: argparse.Namespace) -> None:
    """Unlock and optionally mount dataset"""
    require_root()
    require_commands(["zfs"])
    cfg        = ensure_config(Path(args.c))
    dataset    = resolve_dataset(cfg, args.d)
    entry      = dataset_entry(cfg, dataset)
    rp_id      = args.r or entry.get("rp_id", "zfs.local")
    zfsops.ensure_keylocation_prompt(dataset)
    key_status = zfsops.zfs_get(dataset, "keystatus")
    if   key_status == "available":
        eprint(f"ZFS key already loaded for {dataset}")
    elif key_status == "unavailable":
        key_format    = zfsops.zfs_get(dataset, "keyformat").strip().lower()
        name, wrapper = choose_wrapper(entry, args.n)
        raw_key       = unwrap_key_record(wrapper, rp_id=rp_id, cfg=cfg, fido_device=args.D)
        try:
            if key_format == "hex":
                key_hex = raw_key.hex()
                zfsops.load_key_hex(dataset, key_hex, dry_run=True)
                zfsops.load_key_hex(dataset, key_hex, dry_run=False)
            else:
                with ScratchSpace(safe_name(dataset)) as scratch:
                    scratch.write_key(raw_key)
                    zfsops.load_key(dataset, scratch.key_path(), dry_run=True)
                    zfsops.load_key(dataset, scratch.key_path(), dry_run=False)
        finally:
            wipe_buffer(raw_key)
        eprint(f"Unlocked {dataset} using wrapper '{name}'")
    elif key_status == "none":
        raise Error(f"dataset is not encrypted: {dataset}")
    else:
        raise Error(f"unexpected keystatus for {dataset}: {key_status}")
    if not args.N:
        zfsops.mount_dataset(dataset)
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def cmd_add(args: argparse.Namespace) -> None:
    """Add another wrapper to an existing dataset"""
    require_root()
    cfg_path = Path(args.c)
    cfg      = ensure_config(cfg_path)
    dataset  = resolve_dataset(cfg, args.d)
    entry    = dataset_entry(cfg, dataset)
    new_name = safe_name(args.n or prompt_value("New wrapper name"))
    old_name, old_wrapper = choose_wrapper(entry, args.o)
    if new_name in entry.setdefault("wrappers", {}) and not args.f:
        raise Error(f"wrapper already exists: {new_name}. Use -f to replace it.")
    use_passphrase, use_fido = resolve_auth_flags(args, prompt=True)
    ensure_fido_backend_available(cfg, use_fido=use_fido)
    rp_id    = args.r or entry.get("rp_id", "zfs.local")
    raw_key  = unwrap_key_record(old_wrapper, rp_id=rp_id, cfg=cfg, fido_device=args.old_fido_device)
    try:
        entry["wrappers"][new_name] = wrap_key_record(raw_key, name=new_name, rp_id=rp_id, cfg=cfg, use_passphrase=use_passphrase, use_fido=use_fido, fido_device=args.new_fido_device)
    finally:
        wipe_buffer(raw_key)
    save_config(cfg_path, cfg)
    print(f"Added wrapper '{new_name}' to {dataset} using existing wrapper '{old_name}'")
    eprint("IMPORTANT: Back up the JSON config again because a new wrapper was added.")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def cmd_lock(args: argparse.Namespace) -> None:
    """Unmount, optionally snapshot, and unload key"""
    require_root()
    cfg     = ensure_config(Path(args.c))
    dataset = resolve_dataset(cfg, args.d)
    zfsops.unmount_dataset(dataset, force_delay=args.F)
    if args.snapshot is not None:
        if zfsops.zfs_get(dataset, "mounted") == "yes":
            raise Error("refusing to snapshot because dataset is still mounted")
        snapshot = zfsops.snapshot_dataset(dataset, args.snapshot)
        eprint(f"Created snapshot {snapshot}")
    zfsops.unload_key(dataset)
    print(f"Locked {dataset}")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def cmd_ensure(args: argparse.Namespace) -> None:
    """Ensure dataset is unlocked and mounted"""
    require_root()
    require_commands(["zfs"])
    cfg = ensure_config(Path(args.c))
    dataset = resolve_dataset(cfg, args.d)
    if zfsops.zfs_get(dataset, "keystatus") == "available" and zfsops.zfs_get(dataset, "mounted") == "yes":
        print(f"{dataset} is already unlocked and mounted")
        return
    unlock_args = argparse.Namespace(c=args.c, d=dataset, n=args.n, D=args.D, r=args.r, N=False)
    cmd_unlock(unlock_args)
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def cmd_backup(args: argparse.Namespace) -> None:
    """Copy JSON config backup"""
    cfg_path = Path(args.c)
    ensure_config(cfg_path)
    out      = Path(args.o)
    if out.exists() and not args.f:
        raise Error(f"output exists: {out}. Use -f to overwrite.")
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(cfg_path, out)
    chmod_private(out)
    if not args.N:
        digest  = hashlib.sha256(out.read_bytes()).hexdigest()
        sidecar = out.with_name(out.name + ".sha256")
        sidecar.write_text(f"{digest}  {out.name}\n", encoding="utf-8")
        chmod_private(sidecar)
    cfg = ensure_config(cfg_path)
    if stamp_all_wrappers_export(cfg, now_utc()):
        save_config(cfg_path, cfg)
    print(f"Backed up JSON config to: {out}")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def cmd_pack(args: argparse.Namespace) -> None:
    """Create tar.gz backup containing the JSON config"""
    cfg_path = Path(args.c)
    cfg      = ensure_config(cfg_path)
    out      = Path(args.o)
    if out.exists() and not args.f:
        raise Error(f"output exists: {out}. Use -f to overwrite.")
    out.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(out, "w:gz") as tar:
        tar.add(cfg_path, arcname=cfg_path.name)
    chmod_private(out)
    cfg.setdefault("backup_evidence", {})["last_pack_at"] = now_utc()
    save_config(cfg_path, cfg)
    print(f"Packed JSON config (UNENCRYPTED archive) to: {out}")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def cmd_export_raw(args: argparse.Namespace) -> None:
    """Dangerously export raw ZFS key"""
    require_root()
    cfg_path      = Path(args.c)
    cfg           = ensure_config(cfg_path)
    dataset       = resolve_dataset(cfg, args.d)
    entry         = dataset_entry(cfg, dataset)
    name, wrapper = choose_wrapper(entry, args.n)
    raw_key       = unwrap_key_record(wrapper, rp_id=args.r or entry.get("rp_id", "zfs.local"), cfg=cfg, fido_device=args.D)
    out           = Path(args.o)
    if out.exists() and not args.f:
        raise Error(f"output exists: {out}. Use -f to overwrite.")
    if not args.y and not prompt_confirm("This writes the raw ZFS key to a file. Continue"):
        raise Error("cancelled")
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        with out.open("wb") as handle:
            handle.write(raw_key)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        wipe_buffer(raw_key)
    chmod_private(out)
    cfg.setdefault("backup_evidence", {})["last_export_raw_at"] = now_utc()
    save_config(cfg_path, cfg)
    print(f"Exported raw key for {dataset} using wrapper '{name}' to: {out}")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def cmd_recover_pending(args: argparse.Namespace) -> None:
    """Finalize config state for an unresolved pending operation"""
    require_root()
    cfg_path = Path(args.c)
    cfg      = ensure_config(cfg_path)
    pending  = cfg.get("pending_op")
    if not pending:
        print("No pending operation found.")
        return
    if args.drop:
        clear_pending_op(cfg)
        save_config(cfg_path, cfg)
        print("Dropped pending operation without finalizing dataset entry.")
        return
    require_commands(["zfs", "zpool"])
    op_id   = str(pending.get("id"))
    dataset = str(pending.get("dataset"))
    entry   = pending.get("entry")
    if not isinstance(entry, dict):
        raise Error("pending operation entry payload is invalid")
    validate_dataset_name(dataset, allow_pool_root=True)
    zpools     = zfsops.list_zpools()
    pool_name  = dataset_pool_name(dataset)
    pool_names = list_pool_names(zpools)
    imported   = imported_pool_names(zpools)
    importable = importable_pool_names(zpools)
    if pool_name not in pool_names:
        available       = ", ".join(sorted(pool_names)) if pool_names else "none"
        raise Error(f"pending recovery refused: zpool not found for dataset '{dataset}': '{pool_name}'. Imported/importable pools: {available}")
    if pool_name not in imported:
        imported_text   = ", ".join(sorted(imported)) if imported else "none"
        importable_text = ", ".join(sorted(importable)) if importable else "none"
        raise Error(f"pending recovery refused: zpool '{pool_name}' is not imported. Imported pools: {imported_text}. Importable pools: {importable_text}")
    live_by_name = {item["name"]: item for item in zfsops.list_datasets() if item.get("name")}
    dataset_live = live_by_name.get(dataset)
    if not dataset_live:
        raise Error(f"pending recovery refused: dataset not found on host: {dataset}")
    if dataset_live.get("encryption", "") == "off":
        raise Error(f"pending recovery refused: dataset is not encrypted: {dataset}")
    # A crash between create/change-key and keylocation reset can leave a stale
    # file:// path; always normalize this during journal recovery.
    zfsops.ensure_keylocation_prompt(dataset)
    if dataset in cfg.get("datasets", {}) and not args.f:
        raise Error(f"dataset already exists in config: {dataset}. Use -f to replace it from pending state.")
    cfg.setdefault("datasets", {})[dataset] = entry
    clear_pending_op(cfg, expected_id=op_id)
    save_config(cfg_path, cfg)
    print(f"Recovered pending operation {op_id} and finalized dataset entry for {dataset}")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def apply_manual_backup(cfg_path: Path) -> None:
    """Manually stamp wrapper backup timestamps"""
    cfg   = ensure_config(cfg_path)
    stamp = now_utc()
    if not stamp_all_wrappers_export(cfg, stamp):
        eprint("WARNING: --manualbackup set, but no wrappers were found to timestamp.")
        return
    save_config(cfg_path, cfg)
    eprint(f"WARNING: manual backup timestamp set to {stamp} for all wrappers.")
    eprint("WARNING: this is not proof of an actual backup; you are responsible for keeping real protected backups.")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser"""
    parser = argparse.ArgumentParser(prog="ezfs2fa", description="Easy FIDO/passphrase-backed OpenZFS dataset protection.")
    parser.add_argument("-c", default=DEFAULT_CONFIG, help=f"JSON config path, default: {DEFAULT_CONFIG}")
    parser.add_argument("--manualbackup", action="store_true", help="manually mark all wrappers as backed up at the current time")
    parser.add_argument("--cancel-pending", action="store_true", help="discard pending operation state before running command")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create JSON config template")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("list", aliases=["ls"], help="list configured datasets and wrappers")
    p.add_argument("-d", help="dataset name")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("doctor", help="show installation and runtime diagnostics")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("fido-list", help="list connected FIDO2 keys")
    p.add_argument("-D", help="show/probe this explicit FIDO2 device path")
    p.set_defaults(func=cmd_fido_list)

    p = sub.add_parser("mkmd", help="create diagnostic scratch filesystem")
    p.add_argument("-n", help="label")
    p.set_defaults(func=cmd_mkmd)

    p = sub.add_parser("create", help="create encrypted dataset or migrate existing one and enrol first wrapper")
    p.add_argument("-d", help="dataset, for example zroot/secure")
    p.add_argument("-m", help="mountpoint, for example /secure")
    p.add_argument("-n", help="first wrapper name")
    p.add_argument("-r", help="FIDO2 relying party id")
    p.add_argument("-D", help="FIDO2 device path")
    p.add_argument("-C", help="ZFS canmount value")
    p.add_argument("--migrate", dest="migrate_dataset", help="migrate existing unlocked encrypted DATASET into ezfs2fa wrappers and rotate key")
    p.add_argument("--hex", action="store_true", dest="hex_key", help="use keyformat=hex; generate random key material and inject it as hex via prompt keylocation")
    p.add_argument("--passphrase", "--pass", action="store_true", dest="passphrase", help="protect wrapper with passphrase")
    p.add_argument("--fido", action="store_true", help="protect wrapper with FIDO2 hmac-secret")
    p.add_argument("-a", action="store_true", help="prompt to add another wrapper after first")
    p.add_argument("-f", action="store_true", help="replace existing config entry")
    p.add_argument("-y", action="store_true", help="assume yes for destructive confirmation")
    p.set_defaults(func=cmd_create)

    p = sub.add_parser("unlock", help="unlock and mount dataset")
    p.add_argument("-d", help="dataset")
    p.add_argument("-n", help="wrapper name")
    p.add_argument("-D", help="FIDO2 device path")
    p.add_argument("-r", help="override relying party id")
    p.add_argument("-N", action="store_true", help="do not mount after load-key")
    p.set_defaults(func=cmd_unlock)

    p = sub.add_parser("add", help="add another wrapper")
    p.add_argument("-d", help="dataset")
    p.add_argument("-o", help="old wrapper name used to unwrap")
    p.add_argument("-n", help="new wrapper name")
    p.add_argument("-r", help="override relying party id")
    p.add_argument(
        "-X", "--old-fido-device",
        dest="old_fido_device",
        metavar="DEV",
        help="FIDO2 device path used to authenticate the existing wrapper",
    )
    p.add_argument(
        "-Y", "--new-fido-device",
        dest="new_fido_device",
        metavar="DEV",
        help="FIDO2 device path used to enrol the new wrapper",
    )
    p.add_argument("--passphrase", "--pass", action="store_true", dest="passphrase", help="protect wrapper with passphrase")
    p.add_argument("--fido", action="store_true", help="protect wrapper with FIDO2 hmac-secret")
    p.add_argument("-f", action="store_true", help="replace existing new wrapper name")
    p.set_defaults(func=cmd_add)

    p = sub.add_parser("lock", help="unmount, optionally snapshot, and unload dataset key")
    p.add_argument("-d", help="dataset")
    p.add_argument("-F", type=int, help="force unmount after this many seconds")
    p.add_argument("-S", "--snapshot", nargs="?", const="", help="snapshot after unmount; optional name")
    p.set_defaults(func=cmd_lock)

    p = sub.add_parser("ensure", help="ensure dataset is unlocked and mounted")
    p.add_argument("-d", help="dataset")
    p.add_argument("-n", help="wrapper name")
    p.add_argument("-D", help="FIDO2 device path")
    p.add_argument("-r", help="override relying party id")
    p.set_defaults(func=cmd_ensure)

    p = sub.add_parser("backup", help="copy JSON config backup")
    p.add_argument("-o", required=True, help="output JSON path")
    p.add_argument("-f", action="store_true", help="overwrite output")
    p.add_argument("-N", action="store_true", help="do not write checksum sidecar")
    p.set_defaults(func=cmd_backup)

    p = sub.add_parser("pack", help="tar.gz backup containing only JSON config")
    p.add_argument("-o", required=True, help="output tar.gz path")
    p.add_argument("-f", action="store_true", help="overwrite output")
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("upgrade-wrappers", help="upgrade legacy wrapper records to current wrapper version")
    p.add_argument("-d", help="dataset")
    p.add_argument("-n", help="wrapper name (requires -d)")
    p.add_argument("-D", help="FIDO2 device path")
    p.add_argument("-y", action="store_true", help="assume yes")
    p.set_defaults(func=cmd_upgrade_wrappers)

    p = sub.add_parser("recover-pending", help="finalize unresolved pending create/migrate operation")
    p.add_argument("-f", action="store_true", help="replace existing dataset entry from pending state")
    p.add_argument("--drop", action="store_true", help="discard pending state without finalizing dataset entry")
    p.set_defaults(func=cmd_recover_pending)

    p = sub.add_parser("export-raw", help="dangerous: export raw ZFS key")
    p.add_argument("-d", help="dataset")
    p.add_argument("-n", help="wrapper name")
    p.add_argument("-D", help="FIDO2 device path")
    p.add_argument("-r", help="override relying party id")
    p.add_argument("-o", required=True, help="output raw key file")
    p.add_argument("-f", action="store_true", help="overwrite output")
    p.add_argument("-y", action="store_true", help="assume yes")
    p.set_defaults(func=cmd_export_raw)

    return parser
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def main(argv: Optional[list[str]] = None) -> int:
    """Entry point"""
    parser = build_parser()
    args   = parser.parse_args(argv)
    try:
        cfg_path = Path(args.c)
        if args.manualbackup:
            apply_manual_backup(cfg_path)
        cfg = ensure_config(cfg_path)
        if args.cancel_pending:
            if cancel_pending_op(cfg_path, cfg):
                eprint("WARNING: pending operation state cleared via --cancel-pending.")
            else:
                eprint("WARNING: --cancel-pending requested, but no pending operation was present.")
        warn_pending_op(cfg)
        ensure_no_pending_for_mutation(cfg, args.cmd)
        try:
            warn_missing_backup_evidence(cfg)
        except Exception as exc:
            eprint(f"WARNING: backup-evidence check skipped: {exc}")
        args.func(args)
        return 0
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130
    except RelaunchRequested:
        eprint("Elevation requested. Continue in the Administrator window.")
        return 0
    except Error as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
if __name__ == "__main__":
    raise SystemExit(main())
# ------------------------------------------------------------------------------
