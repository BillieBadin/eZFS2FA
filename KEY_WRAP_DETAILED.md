# eZFS2FA+ key wrap/unwrap — detailed guide

This document explains the key wrap and unwrap ceremony at the core of `eZFS2FA+` in detail.
It is written for readers who are comfortable with system administration but are not cryptography specialists.

The high-level idea is simple: the real ZFS raw key never changes.
`eZFS2FA+` builds a locked container around it and lets you open that container with a passphrase, a hardware key, or both.

---

## How to picture it

Think of it as a **safe inside a safe**:

- the **inner safe** holds the OpenZFS raw encryption key;
- the **outer safe** is the wrapper record in the JSON file;
- the **combination** is your passphrase, your FIDO2 hardware key, or both together.

When the outer safe opens, the original raw key is recovered and handed to ZFS unchanged.
If the wrong combination is tried, the outer safe does not open: ZFS never sees a wrong key.

---

## ZFS encrypted dataset fundamentals

Understanding a few ZFS concepts first makes the wrapping design much clearer.

### The `encryption` algorithm

When you create a ZFS encrypted dataset you pick an algorithm via `-o encryption=...`.
ZFS offers three key sizes (128, 192, and 256 bits) combined with two AES modes (CCM and GCM):
`aes-128-ccm`, `aes-192-ccm`, `aes-256-ccm`, `aes-128-gcm`, `aes-192-gcm`, `aes-256-gcm`.

`eZFS2FA+` always creates datasets with `-o encryption=on`, which currently resolves to **`aes-256-gcm`** because:

- **256-bit keys** provide the highest protection margin ZFS offers;
- **AES-GCM** is faster than AES-CCM on modern CPUs that have AES-NI hardware acceleration built in.

### The ZFS encryption `keyformat`

The 256-bit (32-byte) encryption key itself needs to be protected too, since storing it in the clear would be pointless.
ZFS supports three `keyformat` modes for this:

- **`raw`** — a 32-byte binary file holds the key directly. ZFS reads it and uses it as-is.
- **`hex`** — same 32-byte key but encoded as 64 hex characters.
- **`passphrase`** — ZFS derives a key from a human-typed passphrase using PBKDF2, storing the derivation parameters itself.

`eZFS2FA+` always uses **`keyformat=raw`** and handles all the passphrase and hardware key logic itself, outside of ZFS.
That design choice gives `eZFS2FA+` full control over key derivation, lets it support multiple independent wrappers for the same dataset, and keeps ZFS's own key storage completely out of the picture.

### What ZFS does and does not encrypt

ZFS encryption is **per-dataset**, not per-pool.
File contents, file attributes, ACLs, and most dataset metadata are fully encrypted.
Some structural metadata, such as dataset names, pool layout, sizes, and quotas, remains visible in plaintext to allow troubleshooting and pool operations without needing to unlock every dataset first.

---

## The factors — 1, 2, or effectively 3

`eZFS2FA+` wraps the ZFS raw key using material derived from one or both of:

- a **passphrase** (something you know, typed at the keyboard);
- a **FIDO2 hardware key** (something you physically own — a YubiKey or compatible token).

If both factors are enrolled in a single wrapper, **both are required** to unlock.
There is no fallback path between factors within one wrapper.

If the FIDO2 token has a PIN configured — which is strongly recommended — then using the FIDO2-only or combined mode effectively gives you three things to satisfy: something you have, something you know, and hardware-enforced lockout after wrong PIN attempts.
That lockout is enforced by the hardware itself and cannot be bypassed by software.

A note on passphrase-only mode: ZFS already offers native passphrase protection via `keyformat=passphrase`.
The main reason to use a passphrase-only wrapper in `eZFS2FA+` is to allow **multiple users to each have their own independent passphrase**, each in their own wrapper, without sharing a secret.

---

## Wrapping: step by step — locking the safe

Here is exactly what happens when `eZFS2FA+` creates a wrapper and locks the raw ZFS key inside it.

### Step 1 — Passphrase derivation with `scrypt` (passphrase mode only)

Raw passphrases must never be used directly as encryption keys.
Even a long passphrase has far less entropy than 32 bytes of proper randomness.
`scrypt` is a deliberately slow and memory-hungry algorithm designed to make brute-force guessing expensive.

**1.1 — Generate a random salt**

A random 16-byte `kdf_salt` is produced by the OS cryptographically secure random number generator (`secrets.token_bytes(16)`).
The salt ensures that two people using the same passphrase end up with completely different derived keys.
This salt is stored in the JSON wrapper.

**1.2 — Run `scrypt` to produce `passphrase_material`**

`hashlib.scrypt(passphrase, salt=kdf_salt, ...)` is called with these parameters:

| Parameter | Value | Meaning |
|-----------|-------|---------|
| `N` | `32768` (`1 << 15`) | Work factor — the main cost dial. Must be a power of two. |
| `r` | `8` | Block size — scales how much memory is used alongside N. |
| `p` | `3` | Parallelisation — adds CPU cost without proportionally adding memory. |
| `dklen` | `64` | Output length in bytes. |

What these parameters mean in practice:

- **Memory**: approximately `128 × N × r` = `128 × 32768 × 8` = **32 MiB** consumed during computation.
- **Time**: on a modern desktop or server, roughly 0.5 to 2 seconds. On a low-power single-board computer like a Raspberry Pi, expect more.

The scrypt output is 64 bytes of deterministic material we call **`passphrase_material`**.
It is the same every time for the same passphrase and the same stored parameters.
All the parameters needed to reproduce it (`kdf_name`, `kdf_salt_b64`, `N`, `r`, `p`, `dklen`) are saved in the JSON wrapper.

> **Aside — why N is on the lighter side:** The original scrypt paper used N=32768 as a 2009 interactive-login baseline. OWASP now recommends N=65536 as a minimum for new systems. The `p=3` partially compensates by tripling CPU cost, but an attacker with parallel hardware benefits more from a higher N than a higher p. The current parameters are reasonable for a tool protecting access that requires physical presence (a FIDO2 key), but if you rely on passphrase alone you are depending heavily on passphrase entropy. A truly random passphrase makes the current parameters more than adequate; a weak passphrase does not.

### Step 2 — FIDO2 `hmac-secret` collection (FIDO2 mode only)

The FIDO2 `hmac-secret` extension lets a hardware key produce a secret that is deterministically bound to a specific credential and a specific salt.
No software can reproduce the output without the physical device.

**2.1 — Create a FIDO2 credential**

The hardware key is used to create a **credential**, identified by a `credential_id`.
This operation uses `fido2-cred` (the `libfido2` command-line tool) and requires the user to enter their PIN (if configured) and then physically touch the key.
The `credential_id_b64` is stored in the JSON wrapper.

**2.2 — Generate a random `hmac_salt`**

A random 32-byte `hmac_salt` is produced by `secrets.token_bytes(32)`.
This salt is stored as `hmac_salt_b64` in the JSON wrapper.

**2.3 — Request the `hmac-secret` assertion**

The hardware key is asked to compute its `hmac-secret` using the stored credential ID, the `hmac_salt`, and the relying party ID.
This operation uses `fido2-assert` and again requires PIN entry and a physical touch.

What the key does internally: it signs the salt in a way that is permanently bound to the credential and the device, then returns a **deterministic 32-byte secret**.
That secret — called **`fido_secret`** — is the same every time as long as the same hardware key, credential, and salt are presented.
Without the physical device, there is no way to produce it; the secret never leaves the hardware.

> The credential creation and the hmac-secret assertion are two separate operations, each requiring a physical touch of the key. On enrolment, both happen in sequence.

### Step 3 — Derive wrap keys with HKDF-SHA-512

At this point we have zero, one, or two blocks of factor material:
- `passphrase_material` (64 bytes, or empty if passphrase not used);
- `fido_secret` (32 bytes, or empty if FIDO2 not used).

Neither of these is used directly as an encryption key.
Instead, they are fed into a two-phase key derivation function called **HKDF** (HMAC-based Key Derivation Function) using SHA-512, which produces two cryptographically independent keys with explicit context binding.

#### Why HKDF and not just a hash?

A plain SHA-512 hash of the concatenated material would work as a key stretcher, but HKDF provides much stronger guarantees:

- **Extract** takes potentially non-uniform input material and produces a proper pseudorandom key.
- **Expand** derives output keys that are cryptographically independent from each other and are bound to a specific, explicit context string.

This means changing any detail of the wrapper — the version, the factor flags, the KDF name — produces a completely different key, automatically, without any extra code.

#### Phase 1 — HKDF-Extract

A pseudorandom key (`prk`) is computed using HMAC-SHA-512:

- **Salt** (the HMAC key for extraction):
  ```
  SHA-512(
      WRAP_VERSION
      + "\0wrap_kdf=" + WRAP_KDF_DEFAULT
      + "\0kdf_name=" + kdf_name
  )
  ```
  This binds the wrapper version and KDF identity into the extraction phase.

- **IKM** (Input Keying Material):
  ```
  "fido_secret=" + fido_secret (or empty bytes)
  + "\0passphrase_material=" + passphrase_material (or empty bytes)
  ```

#### Phase 2 — HKDF-Expand

64 bytes of output keying material are expanded from `prk` using an `info` context string that encodes factor policy:

```
"ezfs2fa-wrap-keys"
+ "\0passphrase=" + ("1" or "0")
+ "\0fido2="      + ("1" or "0")
+ "\0kdf_name="   + kdf_name
```

This binding is crucial: a wrapper that was created with both factors requires both factors to produce the same expanded output.
A wrapper with only one factor enabled will produce a different key even if you supply both factor materials.

The 64-byte HKDF output is split into two independent keys:

- **first 32 bytes → AES-256 key** (used to encrypt the raw ZFS key in step 4);
- **last 32 bytes → HMAC-SHA256 key** (used to compute the integrity tag in step 5).

### Step 4 — Encrypt the raw ZFS key with AES-256-CTR

**4.1 — Generate a random IV**

A random 16-byte `IV` (Initialisation Vector) is produced by `secrets.token_bytes(16)`.
The IV is stored as `iv_b64` in the JSON wrapper.

AES-CTR mode turns AES into a stream cipher: the IV ensures that the same key encrypting the same data always produces different ciphertext.
This is conceptually similar to a salt, but serves a slightly different purpose:

- A **salt** prevents two users with the same passphrase from getting the same derived key.
- An **IV** prevents the same key from producing the same ciphertext twice when applied to identical plaintext.

Since the raw ZFS key is always 32 bytes of fresh randomness anyway, the IV matters less here than in typical scenarios, but it is correct practice and costs nothing.

**4.2 — Encrypt**

The 32-byte raw ZFS key is encrypted using `AES-256-CTR` with the derived AES key and IV.
The output — `ciphertext` — is 32 bytes of opaque data stored as `wrapped_key_b64` in the JSON.
The raw key is not stored anywhere.

### Step 5 — Compute the HMAC-SHA256 integrity tag

The HMAC tag is a **keyed checksum**: only someone who holds the HMAC key can compute or verify it.
It is computed using the derived HMAC-SHA256 key over this authenticated data:

```
WRAP_VERSION
+ "\0passphrase=" + ("1" or "0")
+ "\0fido2="      + ("1" or "0")
+ "\0kdf_name="   + kdf_name
+ "\0" + IV + ciphertext
```

This tag is stored as `tag_b64` in the JSON.

**Why is the HMAC so important?**

AES-CTR is a stream cipher: it will decrypt *anything* with *any* key and produce *some* output.
It has no built-in notion of "this key is wrong" — it just produces 32 bytes no matter what.
Without the HMAC, a wrong passphrase would silently produce garbage that would then be handed to OpenZFS, resulting in a confusing ZFS-level error rather than a clear "wrong passphrase" message.

The HMAC also covers the factor flags and the wrapper version.
This means a forged or modified wrapper — one where someone tried to flip the `"fido2": true` flag to `"fido2": false` to bypass the hardware key requirement — will immediately fail HMAC verification before any decryption is attempted.

### Step 6 — Persist the wrapper record in JSON

The JSON wrapper stores, per wrapper:

- **Factor flags**: `passphrase: true/false`, `fido2: true/false`
- **Wrapper metadata**: `wrap_version`, `wrap_kdf`, `cipher`, `mac`
- **Passphrase KDF metadata** (if passphrase mode): `kdf_name`, `kdf_salt_b64`, `kdf_n`, `kdf_r`, `kdf_p`, `kdf_dklen`
- **FIDO2 metadata** (if FIDO2 mode): `credential_id_b64`, `hmac_salt_b64`, informational device details
- **Crypto output**: `iv_b64`, `wrapped_key_b64`, `tag_b64`
- **Operational metadata**: `created_at`, `last_export_at`, `rp_id`

**The JSON file never contains the raw ZFS key.**

---

## Unwrapping: step by step — opening the safe

Unwrapping is the reverse of wrapping, with one important extra step at the front: version validation.

### Step 1 — Validate the wrapper version

The wrapper's `wrap_version` field must be exactly `ezfs2fa-wrap-v3.0.1`.
If it is not, the tool refuses to proceed and directs you to run `ezfs2fa upgrade-wrappers` first.
This strict version check prevents accidentally using legacy logic on current wrappers or vice versa.

### Step 2 — Read factor flags

The `passphrase` and `fido2` flags in the wrapper tell the tool exactly which factors are required.
Only those factors are collected; no guessing.

### Step 3 — Re-collect factor material

**If passphrase is required:**
The user is prompted for their passphrase.
`scrypt` is run with the parameters stored in the JSON (`kdf_salt_b64`, `N`, `r`, `p`, `dklen`) to reproduce the same `passphrase_material` as at enrolment time.

**If FIDO2 is required:**
The stored `credential_id_b64` and `hmac_salt_b64` are sent to the hardware key via `fido2-assert`.
The user enters their PIN (if configured) and touches the key.
The same 32-byte `fido_secret` is returned — identical to what was produced at enrolment, because the inputs are identical and the hardware is the same.

### Step 4 — Re-derive AES and HMAC keys

The exact same two-phase HKDF-SHA-512 derivation from wrapping step 3 is performed:
same Extract phase with the same salt, same Expand phase with the same context info string.
The result is the same two 32-byte keys as at enrolment — but only if the correct factor material was provided.

### Step 5 — Verify the HMAC tag (integrity before decrypt)

Before attempting any decryption, the tool recomputes the HMAC-SHA256 tag over the authenticated data and compares it against the `tag_b64` stored in JSON using a timing-safe comparison (`hmac.compare_digest`).

If the tag does not match — wrong passphrase, wrong hardware key, or corrupted JSON — the tool stops immediately with a clear error message.
No decryption is attempted.

This ordering — **integrity before decrypt** — is a deliberate security property.
It means you get a useful error right away, and no partial or garbage key material is ever presented to ZFS.

### Step 6 — Decrypt the raw ZFS key

The ciphertext is decrypted using `AES-256-CTR` with the re-derived AES key and the stored IV.
This is the exact inverse of the encryption in wrapping step 4.
The result is the 32-byte raw ZFS key.

### Step 7 — Validate and deliver

The output is validated to be exactly 32 bytes before being written to the volatile RAM-backed scratch filesystem and handed to OpenZFS via a `file://` key location.
Once ZFS has loaded the key, the scratch file is wiped and the scratch filesystem is torn down.

---

## Why the JSON backup matters so much

The JSON file is not just configuration: **it is part of the lock**.

Without the JSON, even holding the correct passphrase and the correct hardware key is not enough to recover the data.
Here is why.

### The passphrase alone is not enough

The `scrypt` function only produces the same `passphrase_material` if given the same salt and parameters.
Those are stored exclusively in the JSON wrapper.
Without `kdf_salt_b64`, `N`, `r`, `p`, and `dklen`, there is no way to reproduce the passphrase material, even with the correct passphrase.

### The FIDO2 key alone is not enough

The FIDO2 key only reproduces its `hmac-secret` when given the exact `credential_id_b64` and `hmac_salt_b64`.
Both are stored exclusively in the JSON wrapper.
Without them, even the correct physical hardware key cannot produce the right `fido_secret`.

### What the JSON stores (and what it does not)

The JSON wrapper contains, in plaintext:

- the IV;
- the HMAC tag;
- the scrypt parameters and salt;
- the FIDO2 credential ID and HMAC salt.

The JSON wrapper contains, encrypted:

- the ciphertext blob (the raw ZFS key, encrypted with AES-256-CTR).

The JSON does **not** contain the raw ZFS key at any point.

The consequence is clear: **back up the JSON file**. Treat the backup with the same care as the hardware key itself — without both, the data is unrecoverable.

If you want a recovery path that is completely independent from the JSON and from `eZFS2FA+`, export the raw ZFS key with `ezfs2fa export-raw` and store it in a secured, offline location. That key file is 32 bytes of raw binary that ZFS can load directly, with no dependency on wrappers, JSON, or any tooling.

---

## Threat model: what each configuration protects against

### Passphrase-only — weakest mode

The JSON file is the only thing between an attacker and the data.
If an attacker obtains the JSON backup, they can mount an offline brute-force attack at full speed, with no lockout, for as long as they like.
The `scrypt` parameters slow them down but do not stop a determined adversary against a weak or moderately strong passphrase.

Protection depends almost entirely on passphrase entropy.
A truly random, long passphrase makes the current scrypt parameters more than adequate.
A human-memorable passphrase often is not strong enough.

Main legitimate use case in `eZFS2FA+`: multiple users each having their own independent passphrase wrapper, without sharing any secret.

### FIDO2-only with a PIN — very high protection

An attacker needs two independent things simultaneously:

**Physical possession of the hardware key** — the `hmac-secret` is computed inside the device and never leaves it.
No amount of compute applied to the JSON alone produces the `fido_secret`.
The JSON is simply useless without the device.

**The PIN** — protects against someone who steals or borrows the physical device.
After a small number of wrong PIN attempts the hardware key locks itself permanently.
This lockout is enforced by the device, not by software, so it cannot be bypassed or reset from outside.

The combination of physical possession and hardware-enforced PIN lockout is qualitatively different from the passphrase-only threat model: it requires the attacker to achieve physical access, not just computational power.

### Passphrase + FIDO2 — best defence in depth

An attacker needs to defeat both factors simultaneously:
- crack the passphrase from the JSON offline; and
- also have physical access to the hardware key.

Those are fundamentally different attack vectors.
In practice, someone who has stolen your hardware key probably has physical access to your system already, which changes the threat model entirely.
But the combined mode adds meaningful protection against narrower threats:

- a theoretical hardware vulnerability that leaks the `hmac-secret` (passphrase becomes the remaining defence);
- a scenario where someone has both the JSON and the hardware key but not the passphrase.

The jump from passphrase-only to FIDO2 is a **qualitative** change in the threat model — from "can be attacked with compute" to "requires physical access."
The jump from FIDO2-only to combined is a **quantitative** improvement within the same physical-access threat model: meaningful as defence in depth, but not transformative for everyday threats.

---

## Summary of the cryptographic design

| Step | What happens |
|------|-------------|
| Passphrase → `passphrase_material` | `scrypt` with per-wrapper random salt and stored parameters |
| FIDO2 → `fido_secret` | `hmac-secret` assertion using stored credential ID and HMAC salt |
| Factor material → keys | Two-phase HKDF-SHA-512: Extract binds factor material; Expand binds factor policy and wrapper context |
| Keys → AES key + HMAC key | First 32 bytes and last 32 bytes of HKDF output |
| Raw ZFS key → ciphertext | AES-256-CTR with random IV |
| Integrity seal | HMAC-SHA256 over wrapper version, factor flags, KDF name, IV, ciphertext |
| JSON stores | Ciphertext, IV, HMAC tag, KDF/FIDO2 metadata — **never the raw key** |

The design choices follow a consistent pattern throughout:

- **Memory-hard passphrase derivation** (`scrypt`) to resist offline brute force.
- **Hardware-bound FIDO2 secret** to require physical possession.
- **Deterministic two-phase HKDF** with explicit context binding so the derived keys are inseparable from the exact wrapper configuration.
- **Integrity before decrypt** so wrong input is caught immediately and cleanly.
- **No raw key storage** anywhere in the JSON, in transit, or on persistent media.
