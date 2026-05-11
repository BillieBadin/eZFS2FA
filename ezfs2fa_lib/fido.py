# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
FIDO CLI backend facade
The Python FIDO backend was deliberately removed. The supported backend is the
libfido2 command-line toolchain: fido2-token, fido2-cred, and fido2-assert.
"""

from   __future__ import annotations

from   typing import Any, Dict, List, Optional

from   .common import Error
from   .fido_cli import CliFidoBackend
from   .fido_common import FidoDeviceInfo

# ------------------------------------------------------------------------------
class FidoManager:
    """Small facade around the CLI FIDO backend"""
    # --------------------------------------------------------------------------
    def __init__(self, _config: Dict[str, Any]) -> None:
        self.backend = CliFidoBackend()
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def list_devices(self) -> List[FidoDeviceInfo]:
        """List visible FIDO2 devices through libfido2 CLI tools"""
        if not self.backend.available():
            raise Error("CLI FIDO backend is unavailable; install libfido2/fido2-tools")
        return self.backend.list_devices()
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def make_credential(self, *, name: str, rp_id: str, device: Optional[str]) -> Dict[str, Any]:
        """Create a FIDO2 hmac-secret credential through the CLI backend"""
        if not self.backend.available():
            raise Error("CLI FIDO backend is unavailable; install libfido2/fido2-tools")
        record = self.backend.make_credential(name=name, rp_id=rp_id, device=device)
        record["backend_used"] = "cli"
        return record
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def hmac_secret(self, *, wrapper: Dict[str, Any], rp_id: str, device: Optional[str]) -> bytes:
        """Request the FIDO2 hmac-secret through the CLI backend"""
        if not self.backend.available():
            raise Error("CLI FIDO backend is unavailable; install libfido2/fido2-tools")
        return self.backend.hmac_secret(wrapper=wrapper, rp_id=rp_id, device=device)
    # --------------------------------------------------------------------------
