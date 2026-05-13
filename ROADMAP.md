# ROADMAP

## Fixes and improvements

- check existing zpools and datasets to prevent (fail fast) trying to create secure dataset in non-existent pool or with ealready existing name; offer better interactive choices

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

