# eZFS2FA+ is a hardened encrypted ZFS dataset interactive workflow offering two-factor authentication for sensitive services on FreeBSD systems, with Linux compatibility built in.
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Billie Badin, SIGORYX Engineering
"""
CLI FIDO backend using libfido2 command-line tools
"""

from   __future__   import annotations
from   typing       import Any, Dict, List, Optional

import base64
import os
import re
import secrets
import subprocess

from   .common      import Error, eprint, require_commands
from   .fido_common import FidoDeviceInfo, choose_from_devices, freebsd_uhid_candidates, ykman_serial_if_single
from   .scratch     import ScratchSpace

# ------------------------------------------------------------------------------
def _wipe_file(path: str) -> None:
    """Overwrite and remove a temporary FIDO file on mdmfs scratch storage"""
    try:
        size = os.path.getsize(path)
        with open(path, "r+b", buffering=0) as handle:
            handle.write(b"\x00" * size)
            handle.flush()
            os.fsync(handle.fileno())
        os.unlink(path)
    except FileNotFoundError:
        return
    except Exception as exc:
        eprint(f"WARNING: failed to wipe temporary FIDO file {path}: {exc}")
        try:
            os.unlink(path)
        except Exception as unlink_exc:
            eprint(f"WARNING: failed to remove temporary FIDO file {path}: {unlink_exc}")
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _write_private(path: str, data: bytes) -> None:
    """Write a 0600 temporary file on mdmfs scratch storage"""
    with open(path, "wb", buffering=0) as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _extract_b64_tokens(text: str) -> List[str]:
    """Return unique base64 candidates from text"""
    tokens: List[str] = []
    seen = set()
    for token in re.findall(r"[A-Za-z0-9+/=]+", text):
        if token in seen:
            continue
        try:
            base64.b64decode(token.encode("ascii"), validate=True)
        except Exception:
            continue
        seen.add(token)
        tokens.append(token)
    return tokens
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _parse_field_candidates(output: bytes) -> List[tuple[str, str]]:
    """Extract (field, b64-token) candidates from textual fido2 output"""
    pairs: List[tuple[str, str]] = []
    for raw in output.decode("utf-8", "replace").splitlines():
        line  = raw.strip()
        if not line:
            continue
        field = ""
        value = line
        for separator in [":", "="]:
            if separator in line:
                head, tail = line.split(separator, 1)
                field = head.strip().lower().replace("_", " ").replace("-", " ")
                value = tail.strip()
                break
        for token in _extract_b64_tokens(value):
            pairs.append((field, token))
    return pairs
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _pick_base64_field(
    output:         bytes,
    *,
    context:        str,
    required_terms: List[str],
    exact_len:      Optional[int] = None,
    min_len:        int = 1,
) -> str:
    """Pick one validated base64 field by name, with strict ambiguity checks"""
    pairs = _parse_field_candidates(output)
    named: List[str] = []
    for field, token in pairs:
        if field and all(term in field for term in required_terms):
            named.append(token)
    source = named if named else [token for _, token in pairs]
    accepted: List[str] = []
    for token in source:
        try:
            decoded = base64.b64decode(token.encode("ascii"), validate=True)
        except Exception:
            continue
        if exact_len is not None and len(decoded) != exact_len:
            continue
        if len(decoded) < min_len:
            continue
        if token not in accepted:
            accepted.append(token)
    if len(accepted) == 1:
        return accepted[0]
    if len(accepted) == 0:
        raise Error(f"unexpected {context} output: required base64 field not found")
    raise Error(f"unexpected {context} output: ambiguous base64 field parse")
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _parse_credential_id_b64(output: bytes) -> str:
    """Extract credential_id_b64 from fido2-cred output"""
    try:
        token = _pick_base64_field(
            output,
            context        = "fido2-cred",
            required_terms = ["credential", "id"],
            min_len        = 16,
        )
    except Error:
        # libfido2 textual output can be positional on some versions. Keep this
        # fallback explicit and validated to avoid silent corruption.
        lines      = [line.strip() for line in output.decode("utf-8", "replace").splitlines() if line.strip()]
        positional = []
        for line in lines:
            tokens = _extract_b64_tokens(line)
            if len(tokens) == 1 and tokens[0] == line:
                positional.append(tokens[0])
        if len(positional) < 5:
            raise Error("unexpected fido2-cred output: cannot extract credential id")
        token   = positional[4]
        decoded = base64.b64decode(token.encode("ascii"), validate=True)
        if len(decoded) < 16:
            raise Error("unexpected fido2-cred output: credential id is too short")
    try:
        base64.b64decode(token.encode("ascii"), validate=True)
    except Exception as exc:
        raise Error(f"fido2-cred returned invalid credential id base64: {exc}") from exc
    return token
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
def _parse_hmac_secret(output: bytes) -> bytes:
    """Extract and decode hmac-secret from fido2-assert output"""
    try:
        token = _pick_base64_field(
            output,
            context        = "fido2-assert",
            required_terms = ["hmac", "secret"],
            exact_len      = 32,
        )
    except Error:
        lines      = [line.strip() for line in output.decode("utf-8", "replace").splitlines() if line.strip()]
        positional = []
        for line in lines:
            tokens = _extract_b64_tokens(line)
            if len(tokens) == 1 and tokens[0] == line:
                positional.append(tokens[0])
        if not positional:
            raise Error("unexpected fido2-assert output: hmac-secret field not found")
        token  = positional[-1]
    try:
        secret = base64.b64decode(token.encode("ascii"), validate=True)
    except Exception as exc:
        raise Error(f"fido2-assert returned invalid hmac-secret base64: {exc}") from exc
    if len(secret) != 32:
        raise Error(f"fido2-assert hmac-secret must be 32 bytes, got {len(secret)}")
    return secret
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
class CliFidoBackend:
    """FIDO backend implemented through fido2-token/fido2-cred/fido2-assert"""

    name = "cli"
    # --------------------------------------------------------------------------
    def available(self) -> bool:
        try:
            require_commands(["fido2-token", "fido2-cred", "fido2-assert"])
            return True
        except Error:
            return False
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def list_devices(self) -> List[FidoDeviceInfo]:
        proc = subprocess.run(["fido2-token", "-L"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        devices_by_path: Dict[str, FidoDeviceInfo] = {}
        serial, serial_source = ykman_serial_if_single()
        if proc.returncode == 0:
            for line in proc.stdout.decode("utf-8", "replace").splitlines():
                if not line.strip():
                    continue
                path, _, text         = line.partition(":")
                path                  = path.strip()
                devices_by_path[path] = FidoDeviceInfo(path=path, label=text.strip() or path, backend=self.name)
        # On FreeBSD, fido2-token -L may prefer /dev/hidraw* when hidraw.ko is loaded.
        # If that path hangs, still probe /dev/uhid* nodes because they may be the working CTAPHID path on Pi-BSD.
        for path in freebsd_uhid_candidates():
            devices_by_path.setdefault(path, FidoDeviceInfo(path=path, label=path, backend=self.name))
        devices: List[FidoDeviceInfo] = []
        for info in devices_by_path.values():
            info.serial        = serial
            info.serial_source = serial_source
            info.responsive    = self._probe(info.path)
            self._fill_token_info(info)
            devices.append(info)
        devices.sort(key=lambda dev: (0 if dev.path.startswith("/dev/uhid") else 1, dev.path))
        return devices
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _probe(self, path: str) -> bool:
        try:
            proc = subprocess.run(["fido2-token", "-I", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except subprocess.TimeoutExpired:
            return False
        return proc.returncode == 0
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _fill_token_info(self, info: FidoDeviceInfo) -> None:
        if   not info.responsive: return
        try:
            proc = subprocess.run(["fido2-token", "-I", info.path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
        except Exception as exc:
            eprint(f"WARNING: failed to query FIDO token info on {info.path}: {exc}")
            return
        if proc.returncode != 0:
            eprint(f"WARNING: fido2-token -I failed for {info.path}")
            return
        for raw in proc.stdout.decode("utf-8", "replace").splitlines():
            line = raw.strip()
            if   line.startswith("aaguid:"):
                info.aaguid         = line.split(":", 1)[1].strip()
            elif line.startswith("version strings:"):
                info.versions       = [item.strip() for item in line.split(":", 1)[1].split(",") if item.strip()]
            elif line.startswith("extension strings:"):
                info.extensions     = [item.strip() for item in line.split(":", 1)[1].split(",") if item.strip()]
            elif line.startswith("options:"):
                opts                = line.split(":", 1)[1].strip()
                info.options["raw"] = opts
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def _choose(self, requested: Optional[str]) -> FidoDeviceInfo:
        """
        An explicit -D path is an operator override. On FreeBSD, /dev/uhid0
        can be a symlink to /dev/u2f/0 and may not appear in fido2-token -L
        when hidraw.ko is loaded. Do not reject it merely because discovery
        did not list it or because a preflight probe timed out. Let the real
        fido2-cred/fido2-assert command be the source of truth.
        """
        if requested:
            if not os.path.exists(requested):
                raise Error(f"requested FIDO device path does not exist: {requested}")
            info                  = FidoDeviceInfo(path=requested, label=requested, backend=self.name, responsive=True)
            serial, serial_source = ykman_serial_if_single()
            info.serial           = serial
            info.serial_source    = serial_source
            self._fill_token_info(info)
            return info
        try:
            return choose_from_devices(self.list_devices(), requested)
        except RuntimeError as exc:
            raise Error(str(exc)) from exc
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def make_credential(self, *, name: str, rp_id: str, device: Optional[str]) -> Dict[str, Any]:
        dev        = self._choose(device)
        challenge  = secrets.token_bytes(32)
        user_id    = secrets.token_bytes(32)
        cred_input = b"\n".join([
            base64.b64encode(challenge),
            rp_id.encode("utf-8"),
            name.encode("utf-8"),
            base64.b64encode(user_id),
        ]) + b"\n"
        print(f"Creating FIDO2 credential '{name}' on {dev.path}. Enter the PIN if prompted, then touch the key when it flashes.")
        # FreeBSD/libfido2 command-line tools are more reliable with explicit
        # -i/-o files than with stdin/stdout. Use mdmfs -M scratch storage so
        # credential material and assertion output do not touch persistent
        # storage.
        with ScratchSpace("fido-cred") as scratch:
            if scratch.mountpoint is None:
                raise Error("FIDO scratch filesystem is not mounted")
            in_path  = str(scratch.mountpoint / "cred.in")
            out_path = str(scratch.mountpoint / "cred.out")
            _write_private(in_path, cred_input)
            output   = b""
            try:
                proc = subprocess.run(["fido2-cred", "-M", "-h", "-v", "-i", in_path, "-o", out_path, dev.path])
                if proc.returncode != 0:
                    raise Error("fido2-cred failed. If the key flashes, touch it after entering the PIN.")
                with open(out_path, "rb") as handle:
                    output = handle.read()
            finally:
                _wipe_file(in_path)
                _wipe_file(out_path)
        credential_id = _parse_credential_id_b64(output)
        return {
            "backend":           self.name,
            "credential_id_b64": credential_id,
            "device":            dev.to_json(),
        }
    # --------------------------------------------------------------------------

    # --------------------------------------------------------------------------
    def hmac_secret(self, *, wrapper: Dict[str, Any], rp_id: str, device: Optional[str]) -> bytes:
        dev = self._choose(device or wrapper.get("device", {}).get("path_at_enrolment"))
        assert_input = b"\n".join([
            base64.b64encode(secrets.token_bytes(32)),
            rp_id.encode("utf-8"),
            wrapper["credential_id_b64"].encode("ascii"),
            wrapper["hmac_salt_b64"].encode("ascii"),
        ]) + b"\n"
        print(f"Requesting FIDO2 hmac-secret from {dev.path}. Enter the PIN if prompted, then touch the key when it flashes.")
        # assert.out contains the hmac-secret output, so keep it on the same
        # volatile mdmfs scratch storage and wipe it immediately after reading.
        with ScratchSpace("fido-assert") as scratch:
            if scratch.mountpoint is None:
                raise Error("FIDO scratch filesystem is not mounted")
            in_path  = str(scratch.mountpoint / "assert.in")
            out_path = str(scratch.mountpoint / "assert.out")
            _write_private(in_path, assert_input)
            output   = b""
            try:
                proc = subprocess.run(["fido2-assert", "-G", "-h", "-v", "-i", in_path, "-o", out_path, dev.path])
                if proc.returncode != 0:
                    raise Error("fido2-assert failed. If the key flashes, touch it after entering the PIN.")
                with open(out_path, "rb") as handle:
                    output = handle.read()
            finally:
                _wipe_file(in_path)
                _wipe_file(out_path)
        return _parse_hmac_secret(output)
    # --------------------------------------------------------------------------
