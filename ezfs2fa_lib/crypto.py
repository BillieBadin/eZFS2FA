# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
Wrapping cryptography
"""

from   __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from   typing import Any, Dict, Optional, Tuple

from   .common import Error, WRAP_VERSION, ZFS_RAW_KEY_BYTES

SCRYPT_N          = 1 << 15
SCRYPT_R          = 8
SCRYPT_P          = 3
SCRYPT_DKLEN      = 64
SCRYPT_SALT_BYTES = 16

# ------------------------------------------------------------------------------
def b64e(data: bytes) -> str:
    """Base64 encode bytes"""
    return base64.b64encode(data).decode("ascii")
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def b64d(text: str) -> bytes:
    """Base64 decode bytes"""
    return base64.b64decode(text.encode("ascii"), validate=True)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def default_kdf_params() -> Dict[str, Any]:
    """Return default per-wrapper scrypt KDF metadata"""
    return {
        "kdf_name":     "scrypt",
        "kdf_salt_b64": b64e(secrets.token_bytes(SCRYPT_SALT_BYTES)),
        "kdf_n":        SCRYPT_N,
        "kdf_r":        SCRYPT_R,
        "kdf_p":        SCRYPT_P,
        "kdf_dklen":    SCRYPT_DKLEN,
    }
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _scrypt_material(passphrase: bytes, kdf_params: Dict[str, Any]) -> bytes:
    """Derive deterministic passphrase material using per-wrapper scrypt params"""
    if kdf_params.get("kdf_name") != "scrypt":
        raise Error(f"unsupported passphrase KDF: {kdf_params.get('kdf_name')}")
    try:
        salt = b64d(str(kdf_params["kdf_salt_b64"]))
        n    = int(kdf_params["kdf_n"])
        r    = int(kdf_params["kdf_r"])
        p    = int(kdf_params["kdf_p"])
        dkln = int(kdf_params["kdf_dklen"])
    except (KeyError, ValueError, TypeError) as exc:
        raise Error(f"invalid KDF metadata in wrapper: {exc}") from exc
    if len(salt) < SCRYPT_SALT_BYTES:
        raise Error("invalid KDF salt length in wrapper")
    if n <= 1 or (n & (n - 1)) != 0:
        raise Error("invalid KDF N parameter (must be power-of-two > 1)")
    if r <= 0 or p <= 0 or dkln <= 0:
        raise Error("invalid KDF parameters (r, p, dklen must be > 0)")
    maxmem = (128 * n * r) + (128 * r * p) + 4096
    return hashlib.scrypt(passphrase, salt=salt, n=n, r=r, p=p, dklen=dkln, maxmem=maxmem)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def derive_wrap_keys(fido_secret: Optional[bytes], passphrase: Optional[bytes], *, passphrase_enabled: bool, fido_enabled: bool, kdf_params: Optional[Dict[str, Any]]) -> Tuple[bytes, bytes]:
    """
    Derive AES and HMAC keys from enabled factors.
    Passphrase material is memory-hard via per-wrapper scrypt metadata.
    """
    if not passphrase_enabled and not fido_enabled:
        raise Error("at least one wrapping factor is required")
    if fido_enabled and fido_secret is None:
        raise Error("missing FIDO2 secret for wrapper that requires FIDO2")
    if passphrase_enabled:
        if passphrase is None:
            raise Error("missing passphrase for wrapper that requires passphrase")
        if not kdf_params:
            raise Error("missing KDF metadata for wrapper that requires passphrase")
        passphrase_material = _scrypt_material(passphrase, kdf_params)
        kdf_name            = str(kdf_params.get("kdf_name", "unknown")).encode("ascii", "strict")
    else:
        passphrase_material = b""
        kdf_name            = b"none"
    material = hashlib.sha512(
        WRAP_VERSION.encode("ascii")
        + b"\0passphrase="  + (b"1" if passphrase_enabled else b"0")
        + b"\0fido2="       + (b"1" if fido_enabled else b"0")
        + b"\0kdf_name="    + kdf_name
        + b"\0fido_secret=" + (fido_secret or b"")
        + b"\0passphrase="  + passphrase_material
    ).digest()
    return material[:32], material[32:]
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def aes_ctr(data: bytes, key: bytes, iv: bytes, decrypt: bool = False) -> bytes:
    """Encrypt/decrypt with in-process AES-256-CTR"""
    if len(key) != 32:
        raise Error("AES key must be 32 bytes")
    if len(iv) != 16:
        raise Error("AES-CTR IV must be 16 bytes")
    try:
        from   cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise Error("missing Python dependency: cryptography (required for in-process AES-CTR)") from exc
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    ctx    = cipher.decryptor() if decrypt else cipher.encryptor()
    return ctx.update(data) + ctx.finalize()
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def tag_payload(mac_key: bytes, iv: bytes, ciphertext: bytes, *, passphrase_enabled: bool, fido_enabled: bool, kdf_name: str) -> bytes:
    """Compute wrapper HMAC"""
    if not kdf_name:
        raise Error("missing KDF name in wrapper metadata")
    data = (
        WRAP_VERSION.encode("ascii")
        + b"\0passphrase=" + (b"1" if passphrase_enabled else b"0")
        + b"\0fido2="      + (b"1" if fido_enabled else b"0")
        + b"\0kdf_name="   + kdf_name.encode("ascii")
        + b"\0"            + iv + ciphertext
    )
    return hmac.new(mac_key, data, hashlib.sha256).digest()
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def validate_raw_key(key: bytes) -> None:
    """Require an OpenZFS raw 256-bit key"""
    if len(key) != ZFS_RAW_KEY_BYTES:
        raise Error(f"raw ZFS key must be exactly {ZFS_RAW_KEY_BYTES} bytes")
# ------------------------------------------------------------------------------
