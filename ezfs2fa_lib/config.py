# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
JSON configuration handling
"""

from   __future__ import annotations

import json
import os
import tempfile
from   pathlib    import Path
from   typing     import Any, Dict, Optional

from   .common    import Error, VERSION, WRAP_VERSION, chmod_private, now_utc
from   .crypto    import WRAP_KDF_DEFAULT

REQUIRED_WRAPPER_FIELDS = {
    "wrap_version",
    "iv_b64",
    "wrapped_key_b64",
    "tag_b64",
    "passphrase",
    "fido2",
    "last_export_at",
}

# ------------------------------------------------------------------------------
def default_config() -> Dict[str, Any]:
    """Return a fresh default configuration object"""
    return {
        "version":    VERSION,
        "created_at": now_utc(),
        "comment":    "Central state for ezfs2fa OpenZFS + FIDO2/passphrase wrapped dataset keys. Back this file up securely.",
        "datasets":   {},
        "backup_evidence": {
            "last_pack_at":       None,
            "last_export_raw_at": None,
        },
        "pending_op": None,
        "defaults":   {
            "rp_id":    "zfs.local",
            "canmount": "noauto",
        },
    }
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def ensure_config(path: Path) -> Dict[str, Any]:
    """Load config, creating a default template if missing"""
    if not path.exists():
        cfg = default_config()
        save_config(path, cfg)
        return cfg
    with path.open("r", encoding="utf-8") as handle:
        cfg = json.load(handle)
    validate_config(cfg)
    return cfg
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def validate_wrapper(name: str, dataset: str, wrapper: Dict[str, Any]) -> None:
    """Validate one wrapper object"""
    missing = REQUIRED_WRAPPER_FIELDS - set(wrapper)
    if missing:
        joined = ", ".join(sorted(missing))
        raise Error(f"invalid config: wrapper '{name}' in '{dataset}' missing fields: {joined}")
    for key in ["wrap_version", "iv_b64", "wrapped_key_b64", "tag_b64"]:
        value = wrapper.get(key)
        if not isinstance(value, str) or not value:
            raise Error(f"invalid config: wrapper '{name}' in '{dataset}' field '{key}' must be a non-empty string")
    if wrapper.get("wrap_version") == WRAP_VERSION:
        if wrapper.get("wrap_kdf") != WRAP_KDF_DEFAULT:
            raise Error(
                f"invalid config: wrapper '{name}' in '{dataset}' has unsupported wrap_kdf "
                f"for {WRAP_VERSION}: {wrapper.get('wrap_kdf')!r}"
            )
    for key in ["passphrase", "fido2"]:
        if not isinstance(wrapper.get(key), bool):
            raise Error(f"invalid config: wrapper '{name}' in '{dataset}' field '{key}' must be boolean")
    if not wrapper.get("passphrase") and not wrapper.get("fido2"):
        raise Error(f"invalid config: wrapper '{name}' in '{dataset}' must enable passphrase and/or fido2")
    if not isinstance(wrapper.get("last_export_at"), (str, type(None))):
        raise Error(f"invalid config: wrapper '{name}' in '{dataset}' field 'last_export_at' must be a string or null")
    if wrapper.get("passphrase"):
        if wrapper.get("kdf_name") != "scrypt":
            raise Error(f"invalid config: wrapper '{name}' in '{dataset}' passphrase wrappers must use kdf_name=scrypt")
        for key in ["kdf_salt_b64", "kdf_n", "kdf_r", "kdf_p", "kdf_dklen"]:
            if key not in wrapper:
                raise Error(f"invalid config: wrapper '{name}' in '{dataset}' missing passphrase KDF field '{key}'")
    if wrapper.get("fido2"):
        for key in ["credential_id_b64", "hmac_salt_b64"]:
            value = wrapper.get(key)
            if not isinstance(value, str) or not value:
                raise Error(f"invalid config: wrapper '{name}' in '{dataset}' missing or invalid FIDO field '{key}'")
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def validate_config(cfg: Dict[str, Any]) -> None:
    """Validate strict config schema (no compatibility migration)"""
    if not isinstance(cfg, dict):
        raise Error("invalid config: top-level JSON must be an object")
    if not isinstance(cfg.get("datasets"), dict):
        raise Error("invalid config: 'datasets' must be an object")
    backup_evidence = cfg.get("backup_evidence")
    if not isinstance(backup_evidence, dict):
        raise Error("invalid config: 'backup_evidence' must be an object")
    if "last_pack_at" not in backup_evidence or "last_export_raw_at" not in backup_evidence:
        raise Error("invalid config: 'backup_evidence' must include last_pack_at and last_export_raw_at")
    if "pending_op" not in cfg:
        raise Error("invalid config: missing 'pending_op'")
    defaults = cfg.get("defaults")
    if not isinstance(defaults, dict):
        raise Error("invalid config: 'defaults' must be an object")
    if not isinstance(defaults.get("rp_id"), str) or not defaults.get("rp_id"):
        raise Error("invalid config: defaults.rp_id must be a non-empty string")
    if not isinstance(defaults.get("canmount"), str) or not defaults.get("canmount"):
        raise Error("invalid config: defaults.canmount must be a non-empty string")
    for dataset, entry in cfg["datasets"].items():
        if not isinstance(entry, dict):
            raise Error(f"invalid config: dataset entry for '{dataset}' must be an object")
        wrappers = entry.get("wrappers")
        if not isinstance(wrappers, dict):
            raise Error(f"invalid config: wrappers for '{dataset}' must be an object")
        for name, wrapper in wrappers.items():
            if not isinstance(wrapper, dict):
                raise Error(f"invalid config: wrapper '{name}' in '{dataset}' must be an object")
            validate_wrapper(name, dataset, wrapper)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def save_config(path: Path, cfg: Dict[str, Any]) -> None:
    """Atomically save config as 0600 JSON"""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    tmp_path     = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(cfg, handle, indent=4, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        chmod_private(tmp_path)
        os.replace(tmp_path, path)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def resolve_dataset(cfg: Dict[str, Any], supplied: Optional[str]) -> str:
    """Resolve dataset from CLI or default to the only configured dataset"""
    datasets = cfg.get("datasets", {})
    if supplied:
        if supplied not in datasets:
            raise Error(f"dataset not found in config: {supplied}")
        return supplied
    if   len(datasets) == 1: return next(iter(datasets))
    if len(datasets) == 0:
        raise Error("no datasets configured; provide -d after creating one")
    raise Error("multiple datasets configured; provide -d DATASET")
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def dataset_entry(cfg: Dict[str, Any], dataset: str) -> Dict[str, Any]:
    """Return dataset entry or fail"""
    datasets = cfg.setdefault("datasets", {})
    if dataset not in datasets:
        raise Error(f"dataset not found in config: {dataset}")
    return datasets[dataset]
# ------------------------------------------------------------------------------
