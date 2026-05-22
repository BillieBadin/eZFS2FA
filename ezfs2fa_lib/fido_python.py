# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
Cross-platform Python FIDO backend based on Yubico python-fido2 examples.
On Windows it uses the native WebAuthn API (WindowsClient).
On non-Windows platforms it uses direct CTAP HID access via Fido2Client.
"""

from   __future__   import annotations

import base64
import getpass
import secrets
from   typing       import Any, Dict, List, Optional, Tuple

from   .common      import Error, current_os, eprint
from   .fido_common import FidoDeviceInfo, choose_from_devices


# ------------------------------------------------------------------------------
def _decode_std_b64(value: str) -> bytes:
    """Decode standard base64 with strict validation"""
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise Error(f"invalid base64 value: {exc}") from exc
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def _decode_websafe_b64(value: str) -> bytes:
    """Decode WebAuthn-style websafe base64 (without required padding)"""
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise Error(f"invalid WebAuthn base64url value: {exc}") from exc
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def _ext_get(mapping: Any, key: str) -> Any:
    """Best-effort accessor for extension outputs"""
    try:
        if hasattr(mapping, key):
            return getattr(mapping, key)
    except Exception:
        pass
    try:
        return mapping.get(key)
    except Exception:
        return None
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def _extract_hmac_output(ext_results: Any) -> bytes:
    """Extract hmacGetSecret.output1 as 32 bytes from extension results"""
    hmac_output = _ext_get(ext_results, "hmac_get_secret")
    if hmac_output is None:
        hmac_output = _ext_get(ext_results, "hmacGetSecret")
    if hmac_output is None:
        raise Error("FIDO2 assertion did not return hmacGetSecret output")
    output1 = _ext_get(hmac_output, "output1")
    if isinstance(output1, bytes):
        if len(output1) != 32:
            raise Error(f"FIDO2 hmacGetSecret output length must be 32 bytes, got {len(output1)}")
        return output1
    if isinstance(output1, str):
        decoded = _decode_websafe_b64(output1)
        if len(decoded) != 32:
            raise Error(f"FIDO2 hmacGetSecret output length must be 32 bytes, got {len(decoded)}")
        return decoded
    if isinstance(hmac_output, bytes):
        if len(hmac_output) != 32:
            raise Error(f"FIDO2 hmacGetSecret output length must be 32 bytes, got {len(hmac_output)}")
        return hmac_output
    raise Error("FIDO2 assertion returned an unexpected hmacGetSecret output format")
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
def _device_path_text(path: Any) -> str:
    """Convert HID descriptor path bytes/str to string"""
    if isinstance(path, bytes):
        try:
            return path.decode("utf-8", "replace")
        except Exception:
            return repr(path)
    return str(path)
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
class _CliInteraction:
    """CLI prompts for python-fido2 non-Windows direct device backend"""

    # --------------------------------------------------------------------------
    def __init__(self) -> None:
        self._pin: Optional[str] = None
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def prompt_up(self) -> None:
        print("\nTouch your authenticator device now...\n")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def request_pin(self, _permissions: Any, _rp_id: Optional[str]) -> Optional[str]:
        if self._pin is None:
            self._pin = getpass.getpass("Enter FIDO2 PIN: ")
        return self._pin
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def request_uv(self, _permissions: Any, _rp_id: Optional[str]) -> bool:
        print("User verification required.")
        return True
    # --------------------------------------------------------------------------
# ------------------------------------------------------------------------------


# ------------------------------------------------------------------------------
class PythonFidoBackend:
    """Cross-platform FIDO backend implemented with python-fido2"""

    name = "python-fido2"

    # --------------------------------------------------------------------------
    def __init__(self) -> None:
        self._api: Optional[Dict[str, Any]] = None
        self._import_error: Optional[str]   = None
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def dependency_message(self) -> str:
        """Return actionable dependency guidance"""
        detail = f" ({self._import_error})" if self._import_error else ""
        if current_os() == "Windows":
            return (
                "Python FIDO backend is unavailable on Windows. Install python package 'fido2' "
                "and ensure Windows WebAuthn is available (Windows 10 1903+)." + detail
            )
        return (
            "Python FIDO backend is unavailable. Install python package 'fido2'. "
            "On Linux/BSD, ensure the process has permission to access FIDO HID devices." + detail
        )
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _load_api(self) -> Optional[Dict[str, Any]]:
        if self._api is not None:
            return self._api
        if self._import_error is not None:
            return None
        try:
            from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
            try:
                from fido2.client.windows import WindowsClient
            except Exception:
                try:
                    from fido2.client import WindowsClient  # type: ignore[attr-defined]
                except Exception:
                    WindowsClient = None
            from fido2.ctap2.extensions import HmacSecretExtension
            from fido2.hid              import CtapHidDevice
            from fido2.server           import Fido2Server
        except Exception as exc:
            self._import_error = str(exc)
            return None
        self._api = {
            "DefaultClientDataCollector": DefaultClientDataCollector,
            "Fido2Client":                Fido2Client,
            "UserInteraction":            UserInteraction,
            "WindowsClient":              WindowsClient,
            "HmacSecretExtension":        HmacSecretExtension,
            "CtapHidDevice":              CtapHidDevice,
            "Fido2Server":                Fido2Server,
        }
        return self._api
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _windows_available(self) -> bool:
        api = self._load_api()
        if api is None: return False
        windows = api.get("WindowsClient")
        if windows is None: return False
        try:
            return bool(windows.is_available())
        except Exception:
            return False
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def available(self) -> bool:
        api = self._load_api()
        if api is None: return False
        if current_os() == "Windows": return self._windows_available()
        return True
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _build_windows_client(self, *, rp_id: str) -> Any:
        api = self._load_api()
        if api is None:
            raise Error(self.dependency_message())
        windows = api.get("WindowsClient")
        if windows is None or not self._windows_available():
            raise Error(self.dependency_message())
        origin = f"https://{rp_id}"
        collector = api["DefaultClientDataCollector"](origin)
        attempts = [
            lambda: windows(collector,  allow_hmac_secret=True),
            lambda: windows(collector),
            lambda: windows(origin,     allow_hmac_secret=True),
            lambda: windows(origin),
        ]
        for construct in attempts:
            try:
                return construct()
            except TypeError:
                continue
        raise Error("cannot construct Windows WebAuthn client from installed python-fido2 version")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _build_hid_client(self, *, dev: Any, rp_id: str) -> Any:
        api = self._load_api()
        if api is None:
            raise Error(self.dependency_message())
        collector = api["DefaultClientDataCollector"](f"https://{rp_id}")
        return api["Fido2Client"](
            dev,
            client_data_collector = collector,
            user_interaction      = _CliInteraction(),
            extensions            = [api["HmacSecretExtension"](allow_hmac_secret=True)],
        )
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _supports_hmac_secret(self, info: Any) -> bool:
        extensions = [str(item).lower() for item in (getattr(info, "extensions", None) or [])]
        return "hmac-secret" in extensions
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _public_key_options(self, options: Any) -> Any:
        public_key = getattr(options, "public_key", None)
        if public_key is not None: return public_key
        if isinstance(options, dict):
            for key in ("publicKey", "public_key"):
                if key in options: return options[key]
        for key in ("publicKey", "public_key"):
            try:
                return options[key]
            except Exception:
                continue
        raise Error("python-fido2 returned unexpected options object (missing public_key)")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _enumerate_hid_candidates(self, *, rp_id: str) -> List[Tuple[FidoDeviceInfo, Any]]:
        api = self._load_api()
        if api is None:
            raise Error(self.dependency_message())
        candidates: List[Tuple[FidoDeviceInfo, Any]] = []
        try:
            hid_devices = list(api["CtapHidDevice"].list_devices())
        except Exception as exc:
            raise Error(f"cannot enumerate FIDO HID devices: {exc}") from exc
        for dev in hid_devices:
            descriptor = getattr(dev, "descriptor", None)
            path       = _device_path_text(getattr(descriptor, "path", getattr(dev, "path", "unknown")))
            vid        = int(getattr(descriptor, "vid", 0) or 0)
            pid        = int(getattr(descriptor, "pid", 0) or 0)
            product    = getattr(descriptor, "product_name", None) or getattr(dev, "product_name", None)
            label      = f"vendor=0x{vid:04x}, product=0x{pid:04x} ({product or 'FIDO device'})"
            info_obj   = FidoDeviceInfo(
                path       = path,
                label      = label,
                backend    = self.name,
                vendor_id  = f"0x{vid:04x}",
                product_id = f"0x{pid:04x}",
                product    = str(product) if product else None,
                responsive = False,
            )
            try:
                client              = self._build_hid_client(dev=dev, rp_id=rp_id)
                info                = client.info
                info_obj.responsive = self._supports_hmac_secret(info)
                info_obj.versions   = [str(item) for item in (getattr(info, "versions", None) or [])]
                info_obj.extensions = [str(item) for item in (getattr(info, "extensions", None) or [])]
                try:
                    options = getattr(info, "options", None)
                    if isinstance(options, dict):
                        info_obj.options = dict(options)
                except Exception:
                    pass
                try:
                    aaguid = getattr(info, "aaguid", None)
                    if aaguid:
                        info_obj.aaguid = str(aaguid)
                except Exception:
                    pass
            except Exception as exc:
                info_obj.options["error"] = str(exc)
            candidates.append((info_obj, dev))
        return candidates
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def list_devices(self) -> List[FidoDeviceInfo]:
        if not self.available():
            raise Error(self.dependency_message())
        if current_os() == "Windows":
            return [
                FidoDeviceInfo(
                    path       = "windows",
                    label      = "//webauthn: Windows WebAuthn system picker",
                    backend    = self.name,
                    responsive = True,
                )
            ]
        return [info for info, _dev in self._enumerate_hid_candidates(rp_id="example.com")]
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _choose_windows(self, requested: Optional[str]) -> FidoDeviceInfo:
        device = self.list_devices()[0]
        if requested and requested not in {"windows", "windows://webauthn", "windows://hello"}:
            eprint(
                "WARNING: explicit Windows FIDO device paths are ignored by the Python WebAuthn backend; "
                "using the system authenticator picker instead."
            )
        return device
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _choose_hid(self, *, rp_id: str, requested: Optional[str]) -> Tuple[FidoDeviceInfo, Any]:
        candidates = self._enumerate_hid_candidates(rp_id=rp_id)
        devices    = [info for info, _dev in candidates]
        if requested:
            for info, dev in candidates:
                if info.path == requested or info.label == requested:
                    if not info.responsive:
                        raise Error(f"requested FIDO device does not support hmac-secret or is not responsive: {requested}")
                    return info, dev
            raise Error(f"requested FIDO device not found: {requested}")
        try:
            selected = choose_from_devices(devices, None)
        except RuntimeError as exc:
            raise Error(str(exc)) from exc
        for info, dev in candidates:
            if info.path == selected.path: return info, dev
        raise Error("selected FIDO device disappeared")
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def make_credential(self, *, name: str, rp_id: str, device: Optional[str]) -> Dict[str, Any]:
        api = self._load_api()
        if api is None:
            raise Error(self.dependency_message())
        if current_os() == "Windows":
            dev_info = self._choose_windows(device)
            server   = api["Fido2Server"]({"id": rp_id, "name": rp_id}, attestation="none")
            user     = {
                "id":   secrets.token_bytes(32),
                "name": name,
            }
            create_options, state = server.register_begin(
                user,
                resident_key_requirement = "discouraged",
                user_verification        = "preferred",
                authenticator_attachment = "cross-platform",
            )
            print(
                f"Creating FIDO2 credential '{name}' via Windows WebAuthn. "
                "Select your security key in the Windows prompt, enter PIN/biometric if requested, then touch the key."
            )
            client = self._build_windows_client(rp_id=rp_id)
            response = client.make_credential({
                **self._public_key_options(create_options),
                "extensions": {"hmacCreateSecret": True},
            })
            auth_data = server.register_complete(state, response)
            if not _ext_get(getattr(response, "client_extension_results", {}), "hmacCreateSecret"):
                eprint("WARNING: hmacCreateSecret was not acknowledged during credential creation; continuing anyway.")
        else:
            dev_info, dev = self._choose_hid(rp_id=rp_id, requested=device)
            server        = api["Fido2Server"]({"id": rp_id, "name": rp_id}, attestation="none")
            user          = {
                "id":   secrets.token_bytes(32),
                "name": name,
            }
            create_options, state = server.register_begin(
                user,
                resident_key_requirement = "discouraged",
                user_verification        = "preferred",
                authenticator_attachment = "cross-platform",
            )
            print(
                f"Creating FIDO2 credential '{name}' on {dev_info.path}. "
                "Enter PIN if prompted, then touch the key when it flashes."
            )
            client   = self._build_hid_client(dev=dev, rp_id=rp_id)
            response = client.make_credential({
                **self._public_key_options(create_options),
                "extensions": {"hmacCreateSecret": True},
            })
            auth_data = server.register_complete(state, response)
        credential = getattr(auth_data, "credential_data", None)
        if credential is None:
            raise Error("FIDO2 registration did not return credential_data")
        credential_id = getattr(credential, "credential_id", None)
        if not isinstance(credential_id, (bytes, bytearray)):
            raise Error("FIDO2 registration returned an invalid credential_id")
        return {
            "backend":           self.name,
            "credential_id_b64": base64.b64encode(bytes(credential_id)).decode("ascii"),
            "device":            dev_info.to_json(),
        }
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def hmac_secret(self, *, wrapper: Dict[str, Any], rp_id: str, device: Optional[str]) -> bytes:
        api = self._load_api()
        if api is None:
            raise Error(self.dependency_message())
        try:
            credential_id = _decode_std_b64(str(wrapper["credential_id_b64"]))
            salt          = _decode_std_b64(str(wrapper["hmac_salt_b64"]))
        except KeyError as exc:
            raise Error(f"wrapper missing required FIDO2 field: {exc}") from exc
        if len(salt) != 32:
            raise Error(f"hmac_salt must be 32 bytes, got {len(salt)}")
        server = api["Fido2Server"]({"id": rp_id, "name": rp_id}, attestation="none")
        request_options, _state = server.authenticate_begin(
            [{"id": credential_id, "type": "public-key"}],
            user_verification = "preferred",
        )
        if current_os() == "Windows":
            self._choose_windows(device or wrapper.get("device", {}).get("path_at_enrolment"))
            print(
                "Requesting FIDO2 hmac-secret via Windows WebAuthn. "
                "Select your security key in the Windows prompt, enter PIN/biometric if requested, then touch the key."
            )
            client = self._build_windows_client(rp_id=rp_id)
        else:
            dev_info, dev = self._choose_hid(
                rp_id     = rp_id,
                requested = device or wrapper.get("device", {}).get("path_at_enrolment"),
            )
            print(
                f"Requesting FIDO2 hmac-secret from {dev_info.path}. "
                "Enter PIN if prompted, then touch the key when it flashes."
            )
            client = self._build_hid_client(dev=dev, rp_id=rp_id)
        selection = client.get_assertion({
            **self._public_key_options(request_options),
            "extensions": {"hmacGetSecret": {"salt1": salt}},
        })
        response = selection.get_response(0)
        return _extract_hmac_output(getattr(response, "client_extension_results", {}))
    # --------------------------------------------------------------------------
