# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
Shared FIDO backend structures
"""

from   __future__ import annotations

import os
import shutil
import subprocess
import sys
from   pathlib import Path
from   dataclasses import dataclass, field
from   typing import Any, Dict, List, Optional, Protocol

# ------------------------------------------------------------------------------
@dataclass
class FidoDeviceInfo:
    """A visible FIDO device"""

    path:          str
    label:         str = ""
    backend:       str = ""
    vendor_id:     Optional[str] = None
    product_id:    Optional[str] = None
    manufacturer:  Optional[str] = None
    product:       Optional[str] = None
    aaguid:        Optional[str] = None
    versions:      List[str] = field(default_factory=list)
    extensions:    List[str] = field(default_factory=list)
    options:       Dict[str, Any] = field(default_factory=dict)
    serial:        Optional[int] = None
    serial_source: Optional[str] = None
    responsive:    bool = True
    # --------------------------------------------------------------------------
    def to_json(self) -> Dict[str, Any]:
        """Return JSON-safe metadata"""
        return {
            "path_at_enrolment": self.path,
            "label":             self.label or self.path,
            "backend":           self.backend,
            "vendor_id":         self.vendor_id,
            "product_id":        self.product_id,
            "manufacturer":      self.manufacturer,
            "product":           self.product,
            "aaguid":            self.aaguid,
            "versions":          self.versions,
            "extensions":        self.extensions,
            "options":           self.options,
            "serial":            self.serial,
            "serial_source":     self.serial_source,
# ------------------------------------------------------------------------------
        }
    # --------------------------------------------------------------------------

# ------------------------------------------------------------------------------
class FidoBackend(Protocol):
    """Protocol for FIDO backends"""

    name: str
    # --------------------------------------------------------------------------
    def available(self) -> bool:
        ...
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def list_devices(self) -> List[FidoDeviceInfo]:
        ...
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def make_credential(self, *, name: str, rp_id: str, device: Optional[str]) -> Dict[str, Any]:
        ...
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def hmac_secret(self, *, wrapper: Dict[str, Any], rp_id: str, device: Optional[str]) -> bytes:
        ...
    # --------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def ykman_serial_if_single() -> tuple[Optional[int], Optional[str]]:
    """
    Return YubiKey serial if ykman sees exactly one connected key.
    This is intentionally best-effort. On FreeBSD without pcscd, some
    yubikey-manager paths can fail because CCID/PCSC is unavailable. This
    must never prevent FIDO2 use, so failures are warnings only.
    """
    ykman = shutil.which("ykman")
    if   ykman is None: return None, None
    debug = os.environ.get("ezfs2fa_DEBUG", "").strip().lower() in {"1", "true", "yes", "on"}
    try:
        proc = subprocess.run(
            [ykman, "list", "--serials"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        print("WARNING: ykman list --serials timed out; continuing without serial metadata", file=sys.stderr)
        return None, None
    except OSError as exc:
        print(f"WARNING: ykman list --serials failed: {exc}; continuing without serial metadata", file=sys.stderr)
        return None, None
    if proc.returncode != 0:
        print("WARNING: ykman list --serials failed; continuing without serial metadata", file=sys.stderr)
        if debug and proc.stderr:
            detail = proc.stderr.decode("utf-8", "replace").strip()
            if detail:
                print(f"WARNING: ykman stderr: {detail}", file=sys.stderr)
        return None, None
    serials = [line.strip() for line in proc.stdout.decode(errors="replace").splitlines() if line.strip()]
    if   len(serials) != 1: return None, None
    try:
        return int(serials[0]), "ykman list --serials"
    except ValueError:
        return None, None
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def freebsd_uhid_candidates() -> List[str]:
    """
    Return /dev/uhid* candidates, sorted numerically where possible.
    libfido2 may list a hidraw path when hidraw.ko is loaded, but on the
    tested Pi-BSD system that path can hang while /dev/uhid0 works.
    The CLI backend should therefore probe visible uhid nodes as fallback candidates.
    """
    # --------------------------------------------------------------------------
    def sort_key(path: Path) -> tuple[int, str]:
        suffix = path.name.replace("uhid", "", 1)
        try:
            return int(suffix), path.name
        except ValueError:
            return 9999, path.name
# ------------------------------------------------------------------------------
    return [str(path) for path in sorted(Path("/dev").glob("uhid*"), key=sort_key)]
    # --------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def choose_from_devices(devices: List[FidoDeviceInfo], requested: Optional[str]) -> FidoDeviceInfo:
    """Select a device from a list"""
    responsive = [dev for dev in devices if dev.responsive]
    if requested:
        for dev in responsive:
            if   dev.path == requested or dev.label == requested: return dev
        raise RuntimeError(f"requested FIDO device not found or not responsive: {requested}")
    if len(responsive) == 0:
        raise RuntimeError("no responsive FIDO2 device found")
    if   len(responsive) == 1: return responsive[0]
    print("Available FIDO2 keys:")
    for index, dev in enumerate(responsive, 1):
        serial = f" serial={dev.serial}" if dev.serial else ""
        print(f"  [{index}] {dev.label or dev.path}{serial} backend={dev.backend}")
    while True:
        answer = input("Select FIDO2 key number: ").strip()
        try:
            idx = int(answer)
            if   1 <= idx <= len(responsive): return responsive[idx - 1]
        except ValueError:
            pass
        print("Invalid selection")
# ------------------------------------------------------------------------------
