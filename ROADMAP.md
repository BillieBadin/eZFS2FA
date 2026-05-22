# ROADMAP

## ZFS operations with `keyformat=hex`

Consider replacing `keyformat=raw keylocation=file://...` by `keyformat=hex keylocation=prompt`.

- It is simpler and easier to audit.
- ZFS operations become ordinary subprocess calls with input_bytes.
- It reduces cleanup risk. No key file, no unmount failure, no stale /var/run/ez2fdp/..., no md device detach failure.
- It improves portability.
- It makes emergency recovery easier because a hex key is text and can be typed by hand.

## Crypto

### Password derivation improvements

Use more aggressive parameters for `scrypt` if passphrase is the only factor (or deprecate this option entirely given it is too weak and redundant with ZFS native passphrase mode, with the exception where multiple users using each a different passphrase is a target scenario).

Use `Argon2id` instead of `scrypt`: it is the algorithm NIST and OWASP now recommend for new systems.
It has better studied side-channel resistance and a cleaner design.

### Shamir's Secret Sharing (SSS)

Add an SSS wrapper option where k-of-n (2-of-3, 2-of-5, etc.) FIDO2 keys are required to derive the key to unlock the wrapped ZFS key.

The `secretsharing` Python package is pure Python and auditable (~200 lines).
HashiCorp Vault, SLIP39 hardware wallet recovery, and many other production systems use the same primitive.

## Backup

Do the raw key backup as `hex` instead of `raw`, this allows easy copy/paste as text.

## Fixes and improvements

Check existing zpools and datasets to prevent  trying to create secure dataset in non-existent pool or with ealready existing name (fail fast), and/or to offer better interactive choices.

## Removable media

- Support importing/exporting pools on removable media and creating/migrating secure datasets on them
- Prompt to use `copies=2` or `copies=3` when the pool doesn't have physical redundancy (mirror or RAID-Z?)
- Add a test script to corrupt blocks on dataset and demonstrate the recovery path
- Add optional host id(s) lock in wrapper to restrict a removable media to certain hosts

## File-backed

- Support creating interactively a file-backed encrypted zpool (great for testing the removable media path and integrity testing with manual block curruption)

## Miscellaneous

- Add a command to remove a wrapper (thank you Vivian for the idea)
- Add ez2 and/or z2f alias(es) for quick command

## One single wrapper for multiple datasets/keys

- Support a single wrapper for multiple datasets and keys

## ProxMox integration

- Integrate the creation of encrypted zvols (for VMs) or datasets (for containers) into ProxMox VE

