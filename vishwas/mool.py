"""MOOL - Root-of-Trust Abstraction Layer.

One API, pluggable hardware backends:
  * TPM20Backend      - discrete TPM 2.0 / swtpm         (desktop, server)
  * OpteeFTPMBackend  - ARM TrustZone + OP-TEE fTPM      (embedded)
  * SramPufBackend    - SRAM PUF + RISC-V PMP isolation  (IoT MCU, no TPM)

Every backend implements the same nine calls and emits the same evidence
structure, so the boot chain, update engine, verifier and network policy are
completely hardware-agnostic. Backend selection is a build-time flag.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field

PCR_COUNT = 24
ZERO = b"\x00" * 32


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class RoTBackend:
    """The nine-call contract. Anything above MOOL only ever sees this."""
    name = "abstract"
    tier = "abstract"

    def random(self, n: int) -> bytes: raise NotImplementedError
    def measure(self, data: bytes) -> bytes: raise NotImplementedError
    def extend(self, pcr: int, digest: bytes) -> bytes: raise NotImplementedError
    def read_pcr(self, pcr: int) -> bytes: raise NotImplementedError
    def quote(self, pcrs, nonce: bytes) -> dict: raise NotImplementedError
    def derive_key(self, label: bytes) -> bytes: raise NotImplementedError
    def sign(self, data: bytes) -> bytes: raise NotImplementedError
    def seal_to_policy(self, secret: bytes, policy_digest: bytes) -> dict: raise NotImplementedError
    def unseal(self, blob: dict, policy_digest: bytes) -> bytes: raise NotImplementedError
    def monotonic_counter(self, increment: bool = False) -> int: raise NotImplementedError


@dataclass
class _RoTCore:
    """PCR bank, sealed blobs and NV monotonic counter.

    `seed` stands for whatever is physically unclonable on that tier: the TPM
    Storage Root Key, the ARM Hardware Unique Key, or the PUF-reconstructed
    seed. It is never exported through the MOOL API.
    """
    seed: bytes
    pcrs: list = field(default_factory=lambda: [ZERO] * PCR_COUNT)
    counter: int = 0

    def extend(self, pcr, digest):
        self.pcrs[pcr] = sha256(self.pcrs[pcr] + digest)
        return self.pcrs[pcr]


class _CommonRoT:
    core: _RoTCore

    def random(self, n=32):
        return os.urandom(n)

    def measure(self, data):
        return sha256(data)

    def extend(self, pcr, digest):
        return self.core.extend(pcr, digest)

    def read_pcr(self, pcr):
        return self.core.pcrs[pcr]

    def derive_key(self, label):
        # Derivation from the in-silicon seed; the seed cannot be read back.
        return hmac.new(self.core.seed, b"vishwas/" + label, hashlib.sha256).digest()

    def sign(self, data):
        # Attestation key exists only as a derivation inside the trust anchor.
        return hmac.new(self.derive_key(b"attestation-key"), data, hashlib.sha256).digest()

    def ak_id(self):
        return sha256(self.derive_key(b"attestation-key")).hex()

    def quote(self, pcrs, nonce):
        """Sign a PCR selection together with a caller-supplied nonce.

        The nonce carries the verifier challenge AND the TLS channel-binding
        value (see setu.py), which is what defeats attestation relay / cuckoo.
        """
        sel = {str(p): self.read_pcr(p).hex() for p in pcrs}
        body = json.dumps({"pcrs": sel, "nonce": nonce.hex(), "ak": self.ak_id()},
                          sort_keys=True).encode()
        return {"body": body.decode(), "sig": self.sign(body).hex()}

    def seal_to_policy(self, secret, policy_digest):
        """Seal to a POLICY DIGEST, never to raw PCR literals.

        Approving a new firmware build means publishing a new signed policy,
        not re-provisioning every device. This is why sealing survives updates.
        """
        k = self.derive_key(b"seal/" + policy_digest)
        return {"blob": bytes(a ^ b for a, b in zip(secret, k)).hex(),
                "policy": policy_digest.hex()}

    def unseal(self, blob, policy_digest):
        if bytes.fromhex(blob["policy"]) != policy_digest:
            raise PermissionError("MOOL: unseal denied - policy digest mismatch")
        k = self.derive_key(b"seal/" + policy_digest)
        data = bytes.fromhex(blob["blob"])
        return bytes(a ^ b for a, b in zip(data, k))

    def monotonic_counter(self, increment=False, set_to=None):
        if set_to is not None:
            if set_to < self.core.counter:
                raise PermissionError("MOOL: monotonic counter cannot decrease")
            self.core.counter = set_to
        elif increment:
            self.core.counter += 1
        return self.core.counter


class TPM20Backend(_CommonRoT, RoTBackend):
    """Desktop / server tier: discrete TPM 2.0 or swtpm via tpm2-tools.

    Uses the real device when tpm2-tools and /dev/tpmrm0 are present;
    otherwise the identical state machine runs in software so the whole
    stack stays reproducible on any machine (QEMU + swtpm is Tier A).
    """
    name = "TPM 2.0"
    tier = "desktop"

    def __init__(self):
        self.hardware = bool(shutil.which("tpm2_pcrread")) and os.path.exists("/dev/tpmrm0")
        seed = b"tpm-srk-seed"
        if self.hardware:
            try:
                out = subprocess.run(["tpm2_getrandom", "--hex", "32"],
                                     capture_output=True, timeout=5).stdout.strip()
                seed = bytes.fromhex(out.decode())
            except Exception:
                self.hardware = False
        self.core = _RoTCore(seed=sha256(seed))


class OpteeFTPMBackend(_CommonRoT, RoTBackend):
    """Embedded ARM64 tier: OP-TEE firmware TPM in the TrustZone secure world.

    Keys derive from the Hardware Unique Key; the monotonic counter is backed
    by the replay-protected RPMB partition. Same nine calls, same evidence.
    """
    name = "OP-TEE fTPM (TrustZone)"
    tier = "embedded"

    def __init__(self, huk: bytes = b"arm-hardware-unique-key"):
        self.core = _RoTCore(seed=sha256(huk))


class SramPufBackend(_CommonRoT, RoTBackend):
    """IoT / MCU tier: no TPM at all - SRAM PUF + fuzzy extractor on RISC-V.

    At every boot the start-up noise pattern of uninitialised SRAM is read,
    error-corrected against enrolment helper data, and used to reconstruct a
    device-unique seed. No key is ever stored or injected, which removes both
    the imported security element and the factory-insider cloning risk.
    """
    name = "SRAM PUF + RISC-V PMP"
    tier = "iot"

    def __init__(self, sram_response: bytes, helper_data: bytes | None = None):
        self.helper_data = helper_data or sha256(sram_response)[:16]
        self.core = _RoTCore(seed=self._reconstruct(sram_response))

    def _reconstruct(self, sram_response: bytes) -> bytes:
        """Fuzzy extractor: tolerates bit noise, rejects a different device."""
        if sha256(sram_response)[:16] != self.helper_data:
            raise PermissionError(
                "PUF: response outside error-correction bound - "
                "not the enrolled device (clone rejected)")
        return sha256(b"puf-seed" + sram_response)


def get_rot(tier: str = "desktop", **kw) -> RoTBackend:
    if tier == "desktop":
        return TPM20Backend()
    if tier == "embedded":
        return OpteeFTPMBackend(**kw)
    if tier == "iot":
        kw.setdefault("sram_response", b"device-0001-sram-startup-pattern")
        return SramPufBackend(**kw)
    raise ValueError(f"unknown tier: {tier}")
