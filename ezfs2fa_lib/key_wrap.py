# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
Current-version wrapper create/unwrap logic.
Backward-compatibility unwrap for previous version is in wrapper_upgrade.py.
"""

from   __future__ import annotations

import getpass
import hmac
import secrets
from   typing     import Any, Dict, Optional

from   .common    import Error, WRAP_VERSION, now_utc
from   .crypto    import (
    WRAP_KDF_DEFAULT,
    aes_ctr, b64d, b64e,
    default_kdf_params, derive_wrap_keys,
    tag_payload, validate_raw_key, wipe_buffer,
)
from   .fido      import FidoManager

# ------------------------------------------------------------------------------
def _prompt_passphrase(confirm: bool = False) -> bytearray:
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
def wrap_key_record(
    raw_key:        bytearray,
    *,
    name:           str,
    rp_id:          str,
    cfg:            Dict[str, Any],
    use_passphrase: bool,
    use_fido:       bool,
    fido_device:    Optional[str]
) -> Dict[str, Any]:
    """Create a wrapped-key JSON record"""
    if not isinstance(raw_key, bytearray):
        raise Error("raw_key must be a mutable bytearray")
    validate_raw_key(raw_key)
    fido_record: Dict[str, Any]          = {}
    fido_secret: Optional[bytearray]     = None
    passphrase: Optional[bytearray]      = None
    aes_key: Optional[bytearray]         = None
    mac_key: Optional[bytearray]         = None
    try:
        if use_fido:
            manager     = FidoManager(cfg)
            fido_record = manager.make_credential(name=name, rp_id=rp_id, device=fido_device)
            hmac_salt   = secrets.token_bytes(32)
            fido_record["hmac_salt_b64"] = b64e(hmac_salt)
            fido_secret = bytearray(manager.hmac_secret(wrapper=fido_record, rp_id=rp_id, device=fido_device))
        passphrase       = _prompt_passphrase(confirm=True) if use_passphrase else None
        kdf_params       = default_kdf_params() if use_passphrase else {"kdf_name": "none"}
        aes_key, mac_key = derive_wrap_keys(
            fido_secret,
            passphrase,
            passphrase_enabled = use_passphrase,
            fido_enabled       = use_fido,
            kdf_params         = kdf_params,
        )
        iv               = secrets.token_bytes(16)
        ciphertext       = aes_ctr(raw_key, aes_key, iv, decrypt=False)
        tag              = tag_payload(
            mac_key,
            iv,
            ciphertext,
            passphrase_enabled = use_passphrase,
            fido_enabled       = use_fido,
            kdf_name           = str(kdf_params["kdf_name"]),
        )
        record = {
            "name":            name,
            "created_at":      now_utc(),
            "last_export_at":  None,
            "rp_id":           rp_id,
            "passphrase":      use_passphrase,
            "fido2":           use_fido,
            "wrap_version":    WRAP_VERSION,
            "wrap_kdf":        WRAP_KDF_DEFAULT,
            "iv_b64":          b64e(iv),
            "wrapped_key_b64": b64e(ciphertext),
            "tag_b64":         b64e(tag),
            "kdf_name":        kdf_params["kdf_name"],
            "kdf_salt_b64":    kdf_params.get("kdf_salt_b64"),
            "kdf_n":           kdf_params.get("kdf_n"),
            "kdf_r":           kdf_params.get("kdf_r"),
            "kdf_p":           kdf_params.get("kdf_p"),
            "kdf_dklen":       kdf_params.get("kdf_dklen"),
            "cipher":          "AES-256-CTR",
            "mac":             "HMAC-SHA256",
            "auth": {
                "passphrase":  use_passphrase,
                "fido2":       use_fido,
            },
        }
        if use_fido:
            record.update(fido_record)
        return record
    finally:
        wipe_buffer(fido_secret)
        wipe_buffer(passphrase)
        wipe_buffer(aes_key)
        wipe_buffer(mac_key)
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def unwrap_key_record(
    wrapper:     Dict[str, Any],
    *,
    rp_id:       str,
    cfg:         Dict[str, Any],
    fido_device: Optional[str]
) -> bytearray:
    """Unwrap one current-version JSON wrapper into the raw ZFS key"""
    wrapper_version = wrapper.get("wrap_version")
    if wrapper_version != WRAP_VERSION:
        raise Error(
            f"unsupported wrapper version: {wrapper_version}; expected {WRAP_VERSION}. "
            "Run 'ezfs2fa upgrade-wrappers' first."
        )
    use_passphrase = bool(wrapper.get("passphrase", False))
    use_fido       = bool(wrapper.get("fido2", False))
    if not use_passphrase and not use_fido:
        raise Error("wrapper has neither passphrase nor fido2 enabled")
    fido_secret: Optional[bytearray] = None
    passphrase: Optional[bytearray]  = None
    aes_key: Optional[bytearray]     = None
    mac_key: Optional[bytearray]     = None
    try:
        if use_fido:
            fido_secret = bytearray(FidoManager(cfg).hmac_secret(wrapper=wrapper, rp_id=rp_id, device=fido_device))
        passphrase       = _prompt_passphrase(confirm=False) if use_passphrase else None
        kdf_params       = {
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
            passphrase_enabled = use_passphrase,
            fido_enabled       = use_fido,
            kdf_params         = kdf_params,
        )
        iv               = b64d(wrapper["iv_b64"])
        ciphertext       = b64d(wrapper["wrapped_key_b64"])
        expected         = b64d(wrapper["tag_b64"])
        actual           = tag_payload(
            mac_key,
            iv,
            ciphertext,
            passphrase_enabled = use_passphrase,
            fido_enabled       = use_fido,
            kdf_name           = str(wrapper.get("kdf_name", "")),
        )
        if not hmac.compare_digest(expected, actual):
            raise Error("wrapped-key HMAC verification failed; wrong factor, wrong passphrase, or corrupt JSON")
        raw_key = bytearray(aes_ctr(ciphertext, aes_key, iv, decrypt=True))
        validate_raw_key(raw_key)
        return raw_key
    finally:
        wipe_buffer(fido_secret)
        wipe_buffer(passphrase)
        wipe_buffer(aes_key)
        wipe_buffer(mac_key)
# ------------------------------------------------------------------------------
