## Brief summary

`ezfs2fa` provides a hardened unlock workflow for sensitive services on portable FreeBSD systems, with a compatible Linux path for environments that need the same operating model across platforms.

The project starts from a realistic threat model: a small server, laptop, field device, lab system, or Raspberry Pi-class FreeBSD host may be lost, stolen, imaged, or handled by someone who should not get access to its high-value services. The goal is not merely to encrypt a disk. The goal is to keep sensitive services offline by default, keep their secrets in a locked OpenZFS dataset, and make the unlock process explicit, auditable, hardware-backed, and low-residue.

The core workflow is simple:

1. The system boots normally.
2. Sensitive services do **not** start automatically.
3. Their configuration, keys, and private data remain inside a locked OpenZFS encrypted dataset.
4. An operator unlocks the dataset interactively.
5. The unlock can require a FIDO2/YubiKey hardware token, a local passphrase, or both.
6. The dataset mounts and the protected services can start.
7. When finished, services can be stopped, the dataset unmounted, optionally snapshotted, and the ZFS key unloaded again.

FreeBSD remains the first-class target. On FreeBSD, `ezfs2fa` uses OpenZFS native encryption and a volatile `mdmfs -M` scratch filesystem backed by malloc-backed `md(4)` memory. The raw ZFS key is written only as a short-lived 32-byte file inside that volatile scratch filesystem, passed to ZFS through a normal `file://` keylocation, wiped, unmounted, and destroyed. This avoids writing raw unlock material to `/tmp`, `/var/tmp`, `/var/run`, ordinary filesystems, flash storage, or swap-backed temporary storage.

The Linux path follows the same architecture with a Linux-native volatile scratch layer. Instead of FreeBSD `mdmfs -M`, Linux uses `ramfs` for the temporary key workspace. This keeps the user-facing workflow consistent while respecting each operating system’s native mechanisms. The result is a dual-stack design: FreeBSD at the front line, Linux-compatible where portability is useful.

The security model is built on well-understood primitives:

* **OpenZFS native encryption** protects the dataset at rest.
* **FIDO2 `hmac-secret`** binds unlock capability to a physical hardware token.
* **Optional local passphrase wrapping** adds a “something you know” factor.
* **Flexible policy** allows FIDO-only, passphrase-only, or combined FIDO2 plus passphrase wrappers.
* **Multiple enrolled keys** allow redundancy without changing the dataset key.
* **Wrapped key records in one JSON file** make backup practical without exporting the raw ZFS key.
* **Volatile OS-native scratch storage** keeps raw key material away from persistent filesystems.
* **Immediate cleanup** wipes and destroys temporary unlock material after ZFS has loaded the key.
* **Lock-time snapshot support** allows an operator to snapshot after unmount and before unloading the key.

The administrative model is deliberately practical. A single JSON configuration file stores dataset metadata, enrolled wrapper records, FIDO credential material, salts, IVs, ciphertexts, HMAC tags, and convenience metadata such as serial numbers when available. Backing up that JSON file backs up the wrapped-key recovery material, but not the raw OpenZFS key. If raw-key escrow is needed, it remains an explicit, dangerous, operator-requested action.

The package also includes operational commands to create encrypted datasets, enrol additional keys, unlock, ensure a dataset is ready before service startup, back up the JSON state, lock the dataset, force unmount after a delay, and create a lock-time snapshot. This makes it suitable for real service workflows rather than just one-off encryption experiments.

The design is intentionally conservative. FIDO operations currently rely on the proven `libfido2` command-line tooling rather than Python FIDO bindings. ZFS and scratch storage management are performed through native system commands. The code favours explicit, auditable system behaviour over clever abstraction.

In plain terms: `ezfs2fa` turns an OpenZFS dataset into a hardware-backed, optionally passphrase-backed secure compartment for high-value services. It is not magic protection against a live compromised root system. But for the loss, theft, or offline imaging of a powered-off portable system, it provides a strong, clean, thoroughly engineered defensive posture, with FreeBSD as the primary platform and Linux compatibility built into the architecture.

## Licence

This project is licensed under the MIT Licence. See [LICENSE](LICENSE).

Copyright (c) 2026 Billie Badin, SIGORYX Engineering
