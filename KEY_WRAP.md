# eZFS2FA+ key wrap/unwrap

This document explains the current key wrap/unwrap ceremony used by `eZFS2FA+`.

The high-level concept is: keep the real ZFS raw key unchanged; protect it with one or more human-usable factors.

---

## How to picture it

Think of it as a safe inside a safe:

- the inner safe is the OpenZFS raw key;
- the outer safe is the wrapper record in JSON;
- the factors (passphrase and/or FIDO2 key) are what open the outer safe.

If the outer safe opens, the original raw key is recovered exactly and handed over to ZFS.

---

## ZFS encrypted dataset fundamentals

### `encryption` algorithm

OpenZFS supports these encryption suites:
`aes-128-ccm`, `aes-192-ccm`, `aes-256-ccm`, `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`.

`eZFS2FA+` creates datasets with `-o encryption=on`, which currently resolves to `aes-256-gcm`.

### ZFS encryption `keyformat`

OpenZFS supports `keyformat=raw|hex|passphrase`.

- `keyformat=raw` and `keyformat=hex` both represent a 32-byte random key;
- `keyformat=passphrase` derives a key from a passphrase using PBKDF2 metadata stored by ZFS.

`eZFS2FA+` uses `keyformat=raw` only, then performs its own local wrapping around that raw key.

### Additional considerations

ZFS encryption is per-dataset, not full-pool.
Some metadata remains visible for operability (for example dataset names and pool layout), while file contents and most data metadata are encrypted.

---

## eZFS2FA wrapping (high level)

`eZFS2FA+` never mutates the raw ZFS key itself.
It wraps that key using cryptographic material derived from one or two factors:

- a passphrase (something you know);
- a FIDO2 security key (something you have).

If both are enabled, both are required to unwrap.
If the FIDO2 key also requires a PIN, that adds a hardware-enforced knowledge gate on top of possession.

The JSON wrapper stores only the encrypted key plus the metadata needed to reproduce derivation and verify integrity.
It does **not** store the raw key.

---

## Wrapping: step by step (locking the safe)

### 1) Passphrase derivation (`scrypt`) - optional

If passphrase mode is enabled:

1. Generate a random 16-byte `kdf_salt` (`secrets.token_bytes(16)`).
2. Run `hashlib.scrypt(...)` with:
    - `N = 1 << 15` (32768),  - CPU/memory cost parameter
    - `r = 8`,                - block size parameter; scales memory usage alongside N
    - `p = 3`,                - parallelisation factor
    - `dklen = 64`.
3. Store `kdf_name`, salt, and parameters in JSON.

This yields 64 bytes of deterministic `passphrase_material` for the same passphrase + stored KDF metadata.

The standard scrypt memory bound is `128 * N * r` bytes (about 32 MiB with the defaults above).
The implementation adds a conservative padding of `128 * r * p + 4096` bytes on top of that, giving:

```
maxmem = (128 * N * r) + (128 * r * p) + 4096
```

This padding is implementation-specific, not part of the scrypt specification.

### 2) FIDO2 `hmac-secret` collection - optional

If FIDO2 mode is enabled:

1. Create a credential and store its `credential_id_b64`.
2. Generate a random 32-byte `hmac_salt`.
3. Request `hmac-secret` from the token using credential ID + `hmac_salt` + RP ID.

That returns a 32-byte secret (`fido_secret`) bound to that context.
Without the right token and input context, you cannot reproduce it.

The enrolment operation involves two distinct `libfido2` operations:
- credential creation (`fido2-cred`);
- `hmac-secret` assertion (`fido2-assert`).

Each operation requires a physical touch of the key. If the token has a PIN configured, the user must also enter it before each touch. Tokens without a PIN configured proceed on touch alone.

### 3) Derive wrap keys with HKDF-SHA-512 (`wrap_kdf=hkdf-sha512-v1`)

Key derivation runs as two distinct HKDF phases.

**Phase 1 - HKDF-Extract:**

A pseudorandom key (`prk`) is extracted using HMAC-SHA-512:

- The HMAC **salt** is `SHA-512(WRAP_VERSION || "\0wrap_kdf=" || WRAP_KDF_DEFAULT || "\0kdf_name=" || kdf_name)`.
  This binds the wrapper version and KDF identity into the extract phase.
- The HMAC **input keying material (IKM)** is the concatenation of:
    - `"fido_secret="` + `fido_secret` (or empty bytes if FIDO2 is not enabled);
    - `"\0passphrase_material="` + `passphrase_material` (or empty bytes if passphrase is not enabled).

**Phase 2 - HKDF-Expand:**

64 bytes of output keying material are expanded from `prk` using an `info` string that encodes factor policy:

- `"ezfs2fa-wrap-keys"`;
- `"\0passphrase="` + `"1"` or `"0"`;
- `"\0fido2="` + `"1"` or `"0"`;
- `"\0kdf_name="` + `kdf_name`.

This binds the factor flags into the expand phase.

The 64-byte HKDF output is split into:

- first 32 bytes: **AES-256 key**;
- last 32 bytes: **HMAC-SHA256 key** (used to compute the integrity tag in step 5).

### 4) Encrypt the raw ZFS key

1. Generate a random 16-byte `IV`.
2. Encrypt the 32-byte raw key with `AES-256-CTR` using the derived AES key + IV.

### 5) Compute integrity tag

Compute `HMAC-SHA256` using the derived HMAC-SHA256 key over:

- wrapper version context;
- factor flags;
- KDF name;
- `IV || ciphertext`.

This gives fail-fast integrity before any decrypt attempt.

### 6) Persist wrapper record in JSON

Per wrapper, JSON stores:

- factor flags and wrapper version/kdf metadata;
- passphrase KDF metadata (if passphrase mode);
- FIDO2 credential metadata and `hmac_salt` (if FIDO2 mode);
- `iv_b64`, `wrapped_key_b64`, `tag_b64`;
- informational metadata (for example recorded device details).

Again: no raw key is stored.

---

## Unwrapping: step by step (opening the safe)

1. Validate wrapper version is exactly `ezfs2fa-wrap-v3.0.1`.
2. Read factor flags to know which factors are required.
3. Re-collect required factor material:
    - rerun `scrypt` from stored KDF metadata if passphrase is enabled;
    - request FIDO2 `hmac-secret` if FIDO2 is enabled.
4. Re-derive AES/HMAC keys with the same two-phase HKDF context as in wrapping ceremony step 3.
5. Verify HMAC tag first.
6. Decrypt ciphertext with `AES-256-CTR`.
7. Validate output is exactly 32 bytes before giving it to OpenZFS.

The order is deliberate: integrity before decrypt.
CTR mode decrypts any bytes, so HMAC validation is what reliably separates good input from wrong/corrupt input.

---

## Why JSON backup matters so much

The JSON file is not just "config"; it is part of the lock.

It contains critical context:

- `iv_b64`, `tag_b64`, `wrapped_key_b64`;
- factor policy flags;
- KDF metadata;
- FIDO2 credential context.

Consequences:

- passphrase alone is insufficient without matching KDF metadata;
- FIDO2 key alone is insufficient without matching credential/salt context;
- losing JSON can make valid factors unusable.

If you want a recovery path independent from JSON wrapping metadata, export and protect a raw key backup separately.

---

## Threat-model summary

### Passphrase-only

Works, but weakest mode.
If JSON is stolen, attacker gets an offline guessing target.
Strength depends heavily on passphrase entropy.

### FIDO2-only (with PIN configured on token)

Strong practical mode.
Attacker needs physical token and must pass hardware-enforced PIN checks.
No offline brute-force path from JSON alone.

### Passphrase + FIDO2

Best defense in depth.
An attacker needs both cryptographic/offline success and physical factor success.
In real-world attacks, that combined requirement is a meaningful step up.

---

## Bottom line

`eZFS2FA+` keeps OpenZFS key handling simple (`keyformat=raw`) and layers a clear, auditable wrapper around it:

- memory-hard passphrase path (`scrypt`) when enabled;
- hardware-bound FIDO2 secret path when enabled;
- deterministic two-phase HKDF key derivation with explicit context binding at both Extract and Expand;
- explicit integrity-before-decrypt with HMAC.

That gives predictable behavior, strong recoverability rules, and clear failure modes.
