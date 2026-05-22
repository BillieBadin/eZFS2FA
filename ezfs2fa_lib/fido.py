# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
FIDO backend facade with multi-stack backend selection.
"""

from   __future__    import annotations

from   typing        import Any, Dict, List, Optional

from   .common       import Error, current_os
from   .fido_common  import FidoDeviceInfo
from   .fido_cli     import CliFidoBackend
from   .fido_python  import PythonFidoBackend

# ------------------------------------------------------------------------------
class FidoManager:
    """Small facade around the selected FIDO backend"""
    # --------------------------------------------------------------------------
    def __init__(self, _config: Dict[str, Any]) -> None:
        os_name = current_os()
        if os_name == "Windows":
            candidates = [PythonFidoBackend()]
        else:
            candidates = [PythonFidoBackend(), CliFidoBackend()]
        self._diagnostics: List[str] = []
        self.backend = candidates[0]
        for candidate in candidates:
            if candidate.available():
                self.backend = candidate
                break
            detail = candidate.dependency_message() if hasattr(candidate, "dependency_message") else f"{candidate.name} unavailable"
            self._diagnostics.append(f"{candidate.name}: {detail}")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def unavailable_message(self) -> str:
        """Return backend-specific dependency guidance"""
        if self.backend.available(): return ""
        if self._diagnostics:        return "; ".join(self._diagnostics)
        if hasattr(self.backend, "dependency_message"):
            return str(self.backend.dependency_message())
        return "No FIDO backend is available"
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def list_devices(self) -> List[FidoDeviceInfo]:
        """List visible FIDO2 devices through selected backend"""
        if not self.backend.available():
            raise Error(self.unavailable_message())
        return self.backend.list_devices()
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def make_credential(self, *, name: str, rp_id: str, device: Optional[str]) -> Dict[str, Any]:
        """Create a FIDO2 hmac-secret credential through selected backend"""
        if not self.backend.available():
            raise Error(self.unavailable_message())
        record = self.backend.make_credential(name=name, rp_id=rp_id, device=device)
        record["backend_used"] = getattr(self.backend, "name", "unknown")
        return record
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def hmac_secret(self, *, wrapper: Dict[str, Any], rp_id: str, device: Optional[str]) -> bytes:
        """Request the FIDO2 hmac-secret through selected backend"""
        if not self.backend.available():
            raise Error(self.unavailable_message())
        return self.backend.hmac_secret(wrapper=wrapper, rp_id=rp_id, device=device)
    # --------------------------------------------------------------------------
