# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
Wrapping cryptography
"""

from   __future__    import annotations
from   typing        import Any, Dict, Optional, Tuple

import base64
import hashlib
import hmac
import secrets
# from   secretsharing import SecretSharer

from   .common       import Error, WRAP_VERSION, ZFS_RAW_KEY_BYTES

SCRYPT_N          = 1 << 15             # CPU/memory cost parameter
SCRYPT_R          = 8                   # block size parameter; scales memory usage alongside N
SCRYPT_P          = 3                   # parallelisation factor
SCRYPT_DKLEN      = 64                  # derived key length in bytes
SCRYPT_SALT_BYTES = 16                  # salt length
WRAP_KDF_DEFAULT  = "hkdf-sha512-v1"
SecretKeyBytes    = bytearray           # ZFS raw key, passphrase, etc. (mutuatable for in-place wiping)
ByteMaterial      = bytes | bytearray   # Non-secret binary payloads (iv/ciphertext/base64 material)

# ------------------------------------------------------------------------------
def b64e(data: ByteMaterial) -> str:
    """Base64 encode bytes"""
    return base64.b64encode(data).decode("ascii")
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def b64d(text: str) -> bytes:
    """Base64 decode bytes"""
    return base64.b64decode(text.encode("ascii"), validate=True)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def wipe_buffer(buffer: Optional[SecretKeyBytes]) -> None:
    """
    Best-effort in-place wipe for sensitive mutable buffers.
    NOTE: Python and third-party libraries can still keep internal immutable
    copies, so this is defense-in-depth and not a hard memory sanitization
    guarantee.
    """
    if buffer is None: return
    buffer[:] = b"\x00" * len(buffer)
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
def _scrypt_material(
    passphrase: SecretKeyBytes,
    kdf_params: Dict[str, Any]
) -> SecretKeyBytes:
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
    return bytearray(hashlib.scrypt(passphrase, salt=salt, n=n, r=r, p=p, dklen=dkln, maxmem=maxmem))
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _hkdf_expand(
    prk:     SecretKeyBytes,
    info:    bytes,
    out_len: int
) -> SecretKeyBytes:
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
def _derive_wrap_keys_hkdf(
    fido_secret:         SecretKeyBytes,
    passphrase_material: SecretKeyBytes,
    *,
    passphrase_enabled:  bool,
    fido_enabled:        bool,
    kdf_name_bytes:      bytes,
) -> Tuple[SecretKeyBytes, SecretKeyBytes]:
    """HKDF-SHA-512 key derivation for wrapper encryption/MAC keys"""
    salt = hashlib.sha512(
        WRAP_VERSION.encode("ascii")
        + b"\0wrap_kdf=" + WRAP_KDF_DEFAULT.encode("ascii")
        + b"\0kdf_name=" + kdf_name_bytes
    ).digest()
    ikm = (
        b"fido_secret=" + bytes(fido_secret)
        + b"\0passphrase_material=" + bytes(passphrase_material)
    )
    info = (
        b"ezfs2fa-wrap-keys"
        + b"\0passphrase=" + (b"1" if passphrase_enabled else b"0")
        + b"\0fido2="      + (b"1" if fido_enabled else b"0")
        + b"\0kdf_name="   + kdf_name_bytes
    )
    prk = bytearray(hmac.new(salt, ikm, hashlib.sha512).digest())
    try:
        material = _hkdf_expand(prk, info, 64)
        return material[:32], material[32:]
    finally:
        wipe_buffer(prk)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def derive_wrap_keys(
    fido_secret:        Optional[SecretKeyBytes],
    passphrase:         Optional[SecretKeyBytes],
    *,
    passphrase_enabled: bool,
    fido_enabled:       bool,
    kdf_params:         Optional[Dict[str, Any]],
) -> Tuple[SecretKeyBytes, SecretKeyBytes]:
    """
    Derive AES and HMAC keys from enabled factors.
    Passphrase material is memory-hard via per-wrapper scrypt metadata.
    """
    if not passphrase_enabled and not fido_enabled:
        raise Error("at least one wrapping factor is required")
    if fido_secret is not None and not isinstance(fido_secret, SecretKeyBytes):
        raise Error("FIDO2 secret material must be a mutable bytearray")
    if passphrase is not None and not isinstance(passphrase, SecretKeyBytes):
        raise Error("passphrase material must be a mutable bytearray")
    if fido_enabled and fido_secret is None:
        raise Error("missing FIDO2 secret for wrapper that requires FIDO2")
    passphrase_material: SecretKeyBytes = bytearray()
    if passphrase_enabled:
        if passphrase is None:
            raise Error("missing passphrase for wrapper that requires passphrase")
        if not kdf_params:
            raise Error("missing KDF metadata for wrapper that requires passphrase")
        passphrase_material = _scrypt_material(passphrase, kdf_params)
        kdf_name            = str(kdf_params.get("kdf_name", "unknown")).encode("ascii", "strict")
    else:
        kdf_name            = b"none"
    fido_material: SecretKeyBytes = fido_secret if fido_secret is not None else bytearray()
    try:
        return _derive_wrap_keys_hkdf(
            fido_material,
            passphrase_material,
            passphrase_enabled = passphrase_enabled,
            fido_enabled       = fido_enabled,
            kdf_name_bytes     = kdf_name,
        )
    finally:
        wipe_buffer(passphrase_material)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def aes_ctr(
    data:    ByteMaterial,
    key:     SecretKeyBytes,
    iv:      ByteMaterial,
    decrypt: bool = False
) -> bytes:
    """Encrypt/decrypt with in-process AES-256-CTR"""
    if not isinstance(key, SecretKeyBytes):
        raise Error("AES key must be a mutable bytearray")
    if len(key) != 32:
        raise Error("AES key must be 32 bytes")
    if len(iv)  != 16:
        raise Error("AES-CTR IV must be 16 bytes")
    try:
        from   cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise Error("missing Python dependency: cryptography (required for in-process AES-CTR)") from exc
    cipher = Cipher(algorithms.AES(bytes(key)), modes.CTR(bytes(iv)))
    ctx    = cipher.decryptor() if decrypt else cipher.encryptor()
    return ctx.update(bytes(data)) + ctx.finalize()
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def tag_payload(
    mac_key:            SecretKeyBytes,
    iv:                 ByteMaterial,
    ciphertext:         ByteMaterial,
    *,
    passphrase_enabled: bool,
    fido_enabled:       bool,
    kdf_name:           str,
) -> bytes:
    """Compute wrapper HMAC"""
    if not isinstance(mac_key, SecretKeyBytes):
        raise Error("HMAC key must be a mutable bytearray")
    if not kdf_name:
        raise Error("missing KDF name in wrapper metadata")
    data = (
        WRAP_VERSION.encode("ascii")
        + b"\0passphrase=" + (b"1" if passphrase_enabled else b"0")
        + b"\0fido2="      + (b"1" if fido_enabled else b"0")
        + b"\0kdf_name="   + kdf_name.encode("ascii")
        + b"\0"            + bytes(iv) + bytes(ciphertext)
    )
    return hmac.new(bytes(mac_key), data, hashlib.sha256).digest()
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def validate_raw_key(key: SecretKeyBytes) -> None:
    """Require an OpenZFS raw 256-bit key"""
    if not isinstance(key, SecretKeyBytes):
        raise Error("raw ZFS key must be a mutable bytearray")
    if len(key) != ZFS_RAW_KEY_BYTES:
        raise Error(f"raw ZFS key must be exactly {ZFS_RAW_KEY_BYTES} bytes")
# ------------------------------------------------------------------------------
