# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
Volatile scratch filesystem management

FreeBSD uses mdmfs(8) with -M, creating a malloc-backed md(4) disk with UFS.
Linux uses ramfs, mounted directly under /var/run/ezfs2fa.
Windows falls back to a private temporary directory for compatibility.

Both modes expose the same interface: a private mount point containing a
regular key file that OpenZFS can consume through file://...
"""


from   __future__ import annotations

import os
import secrets
import subprocess
import tempfile
from   pathlib    import Path
from   typing     import Optional

from   .common    import Error, ZFS_RAW_KEY_BYTES, chmod_private, current_os, eprint, require_commands, run, safe_name
from   .crypto    import SecretKeyBytes

FREEBSD_SCRATCH_BYTES = 1024 * 1024
IO_BLOCK_BYTES        = 4096
UNIX_RUN_DIR          = Path("/var/run/ezfs2fa")
WINDOWS_RUN_DIR       = Path(tempfile.gettempdir()) / "ezfs2fa"
KEY_FILENAME          = "zfs.rawkey"


# ------------------------------------------------------------------------------
class ScratchSpace:
    """
    Platform-specific volatile scratch filesystem
    On FreeBSD, this creates a malloc-backed md(4) UFS filesystem via:
        mdmfs -M -s 1048576b -p 0700 -w root:wheel -o noatime md <mountpoint>
    On Linux, this creates a ramfs mount via:
        mount -t ramfs -o mode=0700 ramfs <mountpoint>
    On Windows (or any unsupported host), this falls back to a private
    temporary directory. This mode is compatibility-oriented and does not
    provide RAM-backed guarantees.
    The key is stored as a regular file so OpenZFS can use a file:// key
    location. The file is wiped before teardown. On FreeBSD, the backing md
    device is also zeroed where possible before detaching.
    """
    # --------------------------------------------------------------------------
    def __init__(self, label: str = "zfskey") -> None:
        self.label                      = safe_name(label or "zfskey")
        self.os_name                    = current_os()
        self.run_dir                    = UNIX_RUN_DIR if self.os_name in {"FreeBSD", "Linux"} else WINDOWS_RUN_DIR
        self.path: Optional[Path]       = None
        self.mountpoint: Optional[Path] = None
        self.mount_kind: Optional[str]  = None
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def __enter__(self) -> "ScratchSpace":
        self.run_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.run_dir, 0o700)
        except OSError as exc:
            eprint(f"WARNING: failed to set 0700 on scratch run dir {self.run_dir}: {exc}")
        unique          = f"{self.label}.{os.getpid()}.{secrets.token_hex(3)}"
        self.mountpoint = self.run_dir / unique
        self.mountpoint.mkdir(mode=0o700, parents=True, exist_ok=False)
        try:
            if   self.os_name == "FreeBSD":
                self._enter_freebsd()
            elif self.os_name == "Linux":
                self._enter_linux()
            else:
                self._enter_directory()
            try:
                os.chmod(self.mountpoint, 0o700)
            except OSError as exc:
                eprint(f"WARNING: failed to set 0700 on scratch mountpoint {self.mountpoint}: {exc}")
            return self
        except Exception:
            self.destroy()
            raise
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.destroy()
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _enter_freebsd(self) -> None:
        """Create FreeBSD malloc-backed mdmfs scratch"""
        require_commands(["mdmfs", "mdconfig", "mount", "umount"])
        if self.mountpoint is None:
            raise Error("scratch mountpoint is not initialised")
        run([
            "mdmfs",
            "-M",
            "-s", f"{FREEBSD_SCRATCH_BYTES}b",
            "-p", "0700",
            "-w", "root:wheel",
            "-o", "noatime",
            "md",
            str(self.mountpoint),
        ], capture=True)
        self.mount_kind = "freebsd-mdmfs"
        self.path = self._mounted_device()
        if self.path is None:
            raise Error(f"cannot determine md device mounted at {self.mountpoint}")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _enter_linux(self) -> None:
        """Create Linux ramfs scratch"""
        require_commands(["mount", "umount"])
        if self.mountpoint is None:
            raise Error("scratch mountpoint is not initialised")
        run([
            "mount",
            "-t", "ramfs",
            "-o", "mode=0700",
            "ramfs",
            str(self.mountpoint),
        ], capture=True)
        self.mount_kind = "linux-ramfs"
        self.path = None
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _enter_directory(self) -> None:
        """Create compatibility scratch directory when RAM mounts are unavailable"""
        if self.mountpoint is None:
            raise Error("scratch mountpoint is not initialised")
        self.mount_kind = "directory"
        self.path       = None
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _mounted_device(self) -> Optional[Path]:
        """Return /dev/mdX mounted on this mountpoint on FreeBSD"""
        if   self.mountpoint is None: return None
        proc   = subprocess.run(["mount"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        target = str(self.mountpoint)
        for raw_line in proc.stdout.decode("utf-8", "replace").splitlines():
            line   = raw_line.strip()
            marker = f" on {target} "
            if marker not in line:
                continue
            device = line.split(" on ", 1)[0]
            if   device.startswith("/dev/md"): return Path(device)
        return None
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def key_path(self) -> Path:
        """Return the regular key file path"""
        if self.mountpoint is None:
            raise Error("scratch filesystem is not mounted")
        return self.mountpoint / KEY_FILENAME
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def write_key(self, key: SecretKeyBytes) -> None:
        """Write key bytes as a 0600 regular file on volatile scratch"""
        if not isinstance(key, SecretKeyBytes):
            raise Error("scratch key must be a mutable bytearray")
        if len(key) != ZFS_RAW_KEY_BYTES:
            raise Error(f"scratch key must be exactly {ZFS_RAW_KEY_BYTES} bytes")
        key_path = self.key_path()
        self.wipe_key_file()
        with key_path.open("wb", buffering=0) as handle:
            handle.write(key)
            handle.flush()
            os.fsync(handle.fileno())
        chmod_private(key_path)
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def wipe_key_file(self) -> None:
        """Overwrite and remove the key file if present"""
        if   self.mountpoint is None: return
        key_path = self.mountpoint / KEY_FILENAME
        if   not key_path.exists(): return
        try:
            size = key_path.stat().st_size
            with key_path.open("r+b", buffering=0) as handle:
                handle.seek(0)
                handle.write(b"\x00" * size)
                handle.flush()
                os.fsync(handle.fileno())
            key_path.unlink()
        except Exception as exc:
            eprint(f"WARNING: failed to wipe key file {key_path}: {exc}")
            try:
                key_path.unlink()
            except Exception as unlink_exc:
                eprint(f"WARNING: failed to remove key file {key_path}: {unlink_exc}")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _infer_mountpoint(self) -> None:
        """Infer mountpoint from current mount table for manual rmmd/rmscratch"""
        if   self.mountpoint is not None or self.path is None: return
        proc   = subprocess.run(["mount"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        source = str(self.path)
        for raw_line in proc.stdout.decode("utf-8", "replace").splitlines():
            line = raw_line.strip()
            if line.startswith(source + " on "):
                rest = line.split(" on ", 1)[1]
                self.mountpoint = Path(rest.split(" (", 1)[0])
                return
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _zero_freebsd_md(self) -> None:
        """Overwrite md device memory before detach where possible"""
        if   self.path is None or not self.path.exists(): return
        try:
            with self.path.open("r+b", buffering=0) as handle:
                remaining = FREEBSD_SCRATCH_BYTES
                chunk = b"\x00" * IO_BLOCK_BYTES
                while remaining > 0:
                    write_len  = min(len(chunk), remaining)
                    handle.write(chunk[:write_len])
                    remaining -= write_len
                handle.flush()
                os.fsync(handle.fileno())
        except Exception as exc:
            eprint(f"WARNING: failed to wipe FreeBSD md device {self.path}: {exc}")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def destroy(self) -> None:
        """Wipe key file, unmount scratch, and release backing storage"""
        if self.path is None and self.mountpoint is not None and self.os_name == "FreeBSD":
            self.path = self._mounted_device()
        if   self.path is None and self.mountpoint is None: return
        if self.mount_kind in {"freebsd-mdmfs", "linux-ramfs"}:
            self._infer_mountpoint()
        if self.mountpoint is not None:
            self.wipe_key_file()
            if self.path is None and self.os_name == "FreeBSD":
                self.path = self._mounted_device()
            if self.mount_kind in {"freebsd-mdmfs", "linux-ramfs"}:
                umount_proc = subprocess.run(["umount", str(self.mountpoint)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if umount_proc.returncode != 0:
                    eprint(f"WARNING: failed to unmount scratch path {self.mountpoint}")
        if self.os_name == "FreeBSD":
            self._zero_freebsd_md()
            if self.path is not None:
                unit = self.path.name
                if unit.startswith("md") and unit[2:].isdigit():
                    md_proc = subprocess.run(["mdconfig", "-d", "-u", unit[2:]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if md_proc.returncode != 0:
                        eprint(f"WARNING: failed to detach md unit {unit}")
        if self.mountpoint is not None:
            try:
                self.mountpoint.rmdir()
            except OSError as exc:
                eprint(f"WARNING: failed to remove scratch directory {self.mountpoint}: {exc}")
        self.path       = None
        self.mountpoint = None
        self.mount_kind = None
    # --------------------------------------------------------------------------
