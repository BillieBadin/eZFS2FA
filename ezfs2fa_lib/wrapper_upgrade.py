# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
Wrapper upgrade helpers

This module isolates backward-compatibility wrapper-version upgrade logic from
core runtime paths. Core wrapping/unwrapping code remains current-version only.
"""

from   __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import secrets
from   pathlib import Path
from   typing import Any, Dict, List, Optional

from   .common import Error, WRAP_VERSION, prompt_confirm, require_root
from   .config import dataset_entry, ensure_config, save_config
from   .crypto import (
    ByteMaterial,
    SecretKeyBytes,
    WRAP_KDF_DEFAULT,
    aes_ctr,
    b64d,
    b64e,
    derive_wrap_keys,
    tag_payload,
    validate_raw_key,
    wipe_buffer,
)
from   .fido import FidoManager

LEGACY_WRAP_VERSION = "ezfs2fa-wrap-v3.0.0"
LEGACY_WRAP_KDF     = "sha512-v1"

# ------------------------------------------------------------------------------
def wrapper_needs_upgrade(wrapper: Dict[str, Any]) -> bool:
    """Return True when wrapper uses a legacy version"""
    return wrapper.get("wrap_version") == LEGACY_WRAP_VERSION
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _legacy_scrypt_material(passphrase: SecretKeyBytes, wrapper: Dict[str, Any]) -> SecretKeyBytes:
    """Derive legacy per-wrapper passphrase material"""
    if wrapper.get("kdf_name") != "scrypt":
        raise Error(f"unsupported legacy passphrase KDF: {wrapper.get('kdf_name')}")
    try:
        salt = b64d(str(wrapper["kdf_salt_b64"]))
        n    = int(wrapper["kdf_n"])
        r    = int(wrapper["kdf_r"])
        p    = int(wrapper["kdf_p"])
        dkln = int(wrapper["kdf_dklen"])
    except (KeyError, ValueError, TypeError) as exc:
        raise Error(f"invalid legacy KDF metadata in wrapper: {exc}") from exc
    if len(salt) < 16:
        raise Error("invalid legacy KDF salt length in wrapper")
    if n <= 1 or (n & (n - 1)) != 0:
        raise Error("invalid legacy KDF N parameter (must be power-of-two > 1)")
    if r <= 0 or p <= 0 or dkln <= 0:
        raise Error("invalid legacy KDF parameters (r, p, dklen must be > 0)")
    maxmem = (128 * n * r) + (128 * r * p) + 4096
    return bytearray(hashlib.scrypt(passphrase, salt=salt, n=n, r=r, p=p, dklen=dkln, maxmem=maxmem))
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _legacy_derive_wrap_keys(
    *,
    passphrase_enabled: bool,
    fido_enabled:       bool,
    passphrase:         Optional[SecretKeyBytes],
    fido_secret:        Optional[SecretKeyBytes],
    wrapper:            Dict[str, Any],
) -> tuple[SecretKeyBytes, SecretKeyBytes]:
    """Legacy v3.0.0 SHA-512 key combiner"""
    if not passphrase_enabled and not fido_enabled:
        raise Error("legacy wrapper has neither passphrase nor fido2 enabled")
    if passphrase_enabled and passphrase is None:
        raise Error("missing passphrase for legacy wrapper upgrade")
    if fido_enabled and fido_secret is None:
        raise Error("missing FIDO2 secret for legacy wrapper upgrade")
    passphrase_material: SecretKeyBytes = bytearray()
    if passphrase_enabled:
        passphrase_material = _legacy_scrypt_material(passphrase, wrapper)
        kdf_name            = str(wrapper.get("kdf_name", "unknown")).encode("ascii", "strict")
    else:
        kdf_name            = b"none"
    try:
        material = hashlib.sha512(
            LEGACY_WRAP_VERSION.encode("ascii")
            + b"\0passphrase="  + (b"1" if passphrase_enabled else b"0")
            + b"\0fido2="       + (b"1" if fido_enabled else b"0")
            + b"\0kdf_name="    + kdf_name
            + b"\0fido_secret=" + bytes(fido_secret or b"")
            + b"\0passphrase="  + bytes(passphrase_material)
        ).digest()
        return bytearray(material[:32]), bytearray(material[32:])
    finally:
        wipe_buffer(passphrase_material)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _hkdf_expand(prk: SecretKeyBytes, info: bytes, out_len: int) -> SecretKeyBytes:
    """HKDF-Expand using HMAC-SHA512"""
    hash_len = hashlib.sha512().digest_size
    if out_len <= 0:
        raise Error("invalid HKDF output length")
    if out_len > 255 * hash_len:
        raise Error("HKDF output length too large")
    output  = bytearray()
    block   = b""
    counter = 1
    while len(output) < out_len:
        block = hmac.new(bytes(prk), block + info + bytes([counter]), hashlib.sha512).digest()
        output.extend(block)
        counter += 1
    return output[:out_len]
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _legacy_derive_hkdf_keys(
    *,
    passphrase_enabled: bool,
    fido_enabled:       bool,
    passphrase:         Optional[SecretKeyBytes],
    fido_secret:        Optional[SecretKeyBytes],
    wrapper:            Dict[str, Any],
) -> tuple[SecretKeyBytes, SecretKeyBytes]:
    """v3.0.0 HKDF key derivation (transitional wrappers)"""
    if not passphrase_enabled and not fido_enabled:
        raise Error("legacy wrapper has neither passphrase nor fido2 enabled")
    if passphrase_enabled and passphrase is None:
        raise Error("missing passphrase for legacy wrapper upgrade")
    if fido_enabled and fido_secret is None:
        raise Error("missing FIDO2 secret for legacy wrapper upgrade")
    passphrase_material: SecretKeyBytes = bytearray()
    if passphrase_enabled:
        passphrase_material = _legacy_scrypt_material(passphrase, wrapper)
        kdf_name            = str(wrapper.get("kdf_name", "unknown")).encode("ascii", "strict")
    else:
        kdf_name            = b"none"
    prk: Optional[SecretKeyBytes] = None
    try:
        salt = hashlib.sha512(
            LEGACY_WRAP_VERSION.encode("ascii")
            + b"\0wrap_kdf=" + WRAP_KDF_DEFAULT.encode("ascii")
            + b"\0kdf_name=" + kdf_name
        ).digest()
        ikm = (
            b"fido_secret=" + bytes(fido_secret or b"")
            + b"\0passphrase_material=" + bytes(passphrase_material)
        )
        info = (
            b"ezfs2fa-wrap-keys"
            + b"\0passphrase=" + (b"1" if passphrase_enabled else b"0")
            + b"\0fido2="      + (b"1" if fido_enabled else b"0")
            + b"\0kdf_name="   + kdf_name
        )
        prk      = bytearray(hmac.new(salt, ikm, hashlib.sha512).digest())
        material = _hkdf_expand(prk, info, 64)
        return material[:32], material[32:]
    finally:
        wipe_buffer(passphrase_material)
        wipe_buffer(prk)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _legacy_tag_payload(
    *,
    mac_key:            SecretKeyBytes,
    iv:                 ByteMaterial,
    ciphertext:         ByteMaterial,
    passphrase_enabled: bool,
    fido_enabled:       bool,
    kdf_name:           str,
) -> bytes:
    """Legacy v3.0.0 wrapper HMAC computation"""
    if not kdf_name:
        raise Error("missing KDF name in legacy wrapper metadata")
    data = (
        LEGACY_WRAP_VERSION.encode("ascii")
        + b"\0passphrase=" + (b"1" if passphrase_enabled else b"0")
        + b"\0fido2="      + (b"1" if fido_enabled else b"0")
        + b"\0kdf_name="   + kdf_name.encode("ascii")
        + b"\0"            + iv + ciphertext
    )
    return hmac.new(bytes(mac_key), data, hashlib.sha256).digest()
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _unwrap_legacy_wrapper(
    wrapper:     Dict[str, Any],
    *,
    passphrase:  Optional[SecretKeyBytes],
    fido_secret: Optional[SecretKeyBytes],
) -> SecretKeyBytes:
    """Unwrap legacy v3.0.0 wrapper to recover raw key"""
    passphrase_enabled           = bool(wrapper.get("passphrase", False))
    fido_enabled                 = bool(wrapper.get("fido2", False))
    aes_key: Optional[SecretKeyBytes] = None
    mac_key: Optional[SecretKeyBytes] = None
    try:
        wrap_kdf = str(wrapper.get("wrap_kdf", LEGACY_WRAP_KDF))
        if wrap_kdf == LEGACY_WRAP_KDF:
            aes_key, mac_key = _legacy_derive_wrap_keys(
                passphrase_enabled = passphrase_enabled,
                fido_enabled       = fido_enabled,
                passphrase         = passphrase,
                fido_secret        = fido_secret,
                wrapper            = wrapper,
            )
        elif wrap_kdf == WRAP_KDF_DEFAULT:
            aes_key, mac_key = _legacy_derive_hkdf_keys(
                passphrase_enabled = passphrase_enabled,
                fido_enabled       = fido_enabled,
                passphrase         = passphrase,
                fido_secret        = fido_secret,
                wrapper            = wrapper,
            )
        else:
            raise Error(f"unsupported legacy wrap_kdf for upgrade: {wrap_kdf}")
        iv         = b64d(wrapper["iv_b64"])
        ciphertext = b64d(wrapper["wrapped_key_b64"])
        expected   = b64d(wrapper["tag_b64"])
        actual     = _legacy_tag_payload(
            mac_key            = mac_key,
            iv                 = iv,
            ciphertext         = ciphertext,
            passphrase_enabled = passphrase_enabled,
            fido_enabled       = fido_enabled,
            kdf_name           = str(wrapper.get("kdf_name", "")),
        )
        if not hmac.compare_digest(expected, actual):
            raise Error("legacy wrapper HMAC verification failed during upgrade")
        raw_key = bytearray(aes_ctr(ciphertext, aes_key, iv, decrypt=True))
        validate_raw_key(raw_key)
        return raw_key
    finally:
        wipe_buffer(aes_key)
        wipe_buffer(mac_key)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def upgrade_v3_0_0_to_v3_0_1(
    wrapper:     Dict[str, Any],
    *,
    passphrase:  Optional[SecretKeyBytes],
    fido_secret: Optional[SecretKeyBytes],
) -> Dict[str, Any]:
    """Upgrade one wrapper record from v3.0.0 to v3.0.1"""
    if wrapper.get("wrap_version") != LEGACY_WRAP_VERSION:
        raise Error(f"upgrade_v3_0_0_to_v3_0_1 called for non-legacy wrapper version: {wrapper.get('wrap_version')}")
    passphrase_enabled           = bool(wrapper.get("passphrase", False))
    fido_enabled                 = bool(wrapper.get("fido2", False))
    aes_key: Optional[SecretKeyBytes] = None
    mac_key: Optional[SecretKeyBytes] = None
    raw_key: Optional[SecretKeyBytes] = None
    try:
        raw_key = _unwrap_legacy_wrapper(
            wrapper,
            passphrase  = passphrase,
            fido_secret = fido_secret,
        )
        kdf_params = {
            "kdf_name":     wrapper.get("kdf_name"),
            "kdf_salt_b64": wrapper.get("kdf_salt_b64"),
            "kdf_n":        wrapper.get("kdf_n"),
            "kdf_r":        wrapper.get("kdf_r"),
            "kdf_p":        wrapper.get("kdf_p"),
            "kdf_dklen":    wrapper.get("kdf_dklen"),
        }
        aes_key, mac_key = derive_wrap_keys(
            fido_secret,
            passphrase,
            passphrase_enabled = passphrase_enabled,
            fido_enabled       = fido_enabled,
            kdf_params         = kdf_params,
        )
        iv         = secrets.token_bytes(16)
        ciphertext = aes_ctr(raw_key, aes_key, iv, decrypt=False)
        tag        = tag_payload(
            mac_key,
            iv,
            ciphertext,
            passphrase_enabled = passphrase_enabled,
            fido_enabled       = fido_enabled,
            kdf_name           = str(wrapper.get("kdf_name", "none")),
        )
        upgraded = dict(wrapper)
        upgraded["wrap_version"]    = WRAP_VERSION
        upgraded["wrap_kdf"]        = WRAP_KDF_DEFAULT
        upgraded["iv_b64"]          = b64e(iv)
        upgraded["wrapped_key_b64"] = b64e(ciphertext)
        upgraded["tag_b64"]         = b64e(tag)
        return upgraded
    finally:
        wipe_buffer(aes_key)
        wipe_buffer(mac_key)
        wipe_buffer(raw_key)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _prompt_upgrade_passphrase(confirm: bool = False) -> SecretKeyBytes:
    """Prompt for a non-empty wrapping passphrase"""
    first = getpass.getpass("Wrapping passphrase: ")
    if not first:
        raise Error("empty wrapping passphrase refused")
    if confirm:
        second = getpass.getpass("Repeat wrapping passphrase: ")
        if first != second:
            raise Error("passphrases do not match")
    return bytearray(first.encode("utf-8"))
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def cmd_upgrade_wrappers(args: argparse.Namespace) -> None:
    """Upgrade legacy wrapper records to the current wrapper version"""
    require_root()
    cfg_path = Path(args.c)
    cfg      = ensure_config(cfg_path)
    if args.n and not args.d:
        raise Error("wrapper-level upgrade requires -d DATASET when -n is used")
    if args.d:
        datasets = {args.d: dataset_entry(cfg, args.d)}
    else:
        datasets = cfg.get("datasets", {})
    if not datasets:
        raise Error("no datasets configured; nothing to upgrade")
    targets: List[tuple[str, str, Dict[str, Any], Dict[str, Any]]] = []
    unsupported: List[tuple[str, str, str]] = []
    for dataset, entry in sorted(datasets.items()):
        for name, wrapper in sorted(entry.get("wrappers", {}).items()):
            if args.n and name != args.n:
                continue
            if wrapper_needs_upgrade(wrapper):
                targets.append((dataset, name, wrapper, entry))
                continue
            version = str(wrapper.get("wrap_version", ""))
            if version and version != WRAP_VERSION:
                unsupported.append((dataset, name, version))
    if unsupported:
        details = ", ".join(f"{dataset}/{name}={version}" for dataset, name, version in unsupported)
        raise Error(f"unsupported wrapper versions found for upgrade: {details}")
    if not targets:
        print("No legacy wrappers require upgrade.")
        return
    if not args.y:
        print("Wrappers to upgrade:")
        for dataset, name, wrapper, _entry in targets:
            print(f"    {dataset}/{name} version={wrapper.get('wrap_version')}")
        if not prompt_confirm(f"Upgrade {len(targets)} wrapper(s) to {WRAP_VERSION}"):
            raise Error("cancelled")
    upgraded = 0
    for dataset, name, wrapper, entry in targets:
        passphrase:  Optional[SecretKeyBytes] = None
        fido_secret: Optional[SecretKeyBytes] = None
        try:
            if wrapper.get("passphrase"):
                passphrase = _prompt_upgrade_passphrase(confirm=False)
            if wrapper.get("fido2"):
                rp_id       = str(wrapper.get("rp_id") or entry.get("rp_id") or "zfs.local")
                fido_secret = bytearray(FidoManager(cfg).hmac_secret(wrapper=wrapper, rp_id=rp_id, device=args.D))
            entry.setdefault("wrappers", {})[name] = upgrade_v3_0_0_to_v3_0_1(
                wrapper,
                passphrase  = passphrase,
                fido_secret = fido_secret,
            )
            upgraded += 1
            print(f"Upgraded wrapper {dataset}/{name} to {WRAP_VERSION}")
        finally:
            wipe_buffer(passphrase)
            wipe_buffer(fido_secret)
    save_config(cfg_path, cfg)
    print(f"Upgrade complete: {upgraded} wrapper(s) updated.")
# ------------------------------------------------------------------------------
