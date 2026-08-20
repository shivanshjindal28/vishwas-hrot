"""CHHAAP - verified + measured boot chain, with policy sealing.

Each stage VERIFIES the signature of the next before handing over control and
simultaneously MEASURES it into the root of trust, producing a TCG-style event
log. Conventional stacks then seal disk keys to raw PCR values, which breaks on
the first legitimate shim/kernel update - so operators disable sealing. CHHAAP
seals to a signed authorized policy instead: approving a new build means
publishing a new policy, with no re-provisioning and no downtime.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass

from .mool import RoTBackend, sha256

# PCR allocation, mirroring TCG conventions
PCR_FIRMWARE = 0     # BootROM / SPL / UEFI firmware
PCR_BOOTLOADER = 4   # U-Boot FIT or shim + kernel
PCR_POLICY = 7       # secure-boot policy / keys
PCR_ROOTFS = 10      # dm-verity root hash + IMA


@dataclass
class BootStage:
    name: str
    image: bytes
    pcr: int
    signature: bytes | None = None


class BootFailure(Exception):
    """Raised when a stage fails signature verification: control is NOT passed."""


class MeasuredBoot:
    def __init__(self, rot: RoTBackend, platform_key: bytes = b"platform-signing-key"):
        self.rot = rot
        self.platform_key = platform_key
        self.event_log: list[dict] = []

    def sign_stage(self, image: bytes) -> bytes:
        """Stand-in for the vendor signing operation (offline in production)."""
        return hmac.new(self.platform_key, image, hashlib.sha256).digest()

    def _verify(self, stage: BootStage) -> bool:
        return stage.signature is not None and hmac.compare_digest(
            stage.signature, self.sign_stage(stage.image))

    def boot(self, stages: list[BootStage]) -> list[dict]:
        """Verify-then-measure each stage. A failed verification halts the boot."""
        for st in stages:
            if not self._verify(st):
                self.event_log.append({"stage": st.name, "pcr": st.pcr,
                                       "digest": sha256(st.image).hex(), "verified": False})
                raise BootFailure(
                    f"CHHAAP: stage '{st.name}' failed signature verification - boot halted")
            digest = self.rot.measure(st.image)
            self.rot.extend(st.pcr, digest)
            self.event_log.append({"stage": st.name, "pcr": st.pcr,
                                   "digest": digest.hex(), "verified": True})
        return self.event_log


# --- authorized policy ----------------------------------------------------

def policy_digest(approved: dict, owner_key: bytes = b"platform-owner-key") -> bytes:
    """Digest of the platform owner's SIGNED policy: the set of measurement
    states under which secrets may be unsealed. Adding a newly approved build
    = publishing a new signed policy, not re-sealing every device."""
    body = json.dumps(approved, sort_keys=True).encode()
    return sha256(hmac.new(owner_key, body, hashlib.sha256).digest())


def current_state(rot: RoTBackend, pcrs=(PCR_FIRMWARE, PCR_BOOTLOADER, PCR_POLICY, PCR_ROOTFS)) -> dict:
    return {str(p): rot.read_pcr(p).hex() for p in pcrs}


def explain_drift(expected: dict, actual: dict, component_map: dict | None = None) -> list[str]:
    """Deterministic event-log differ.

    This produces the STRUCTURED FACTS; the advisory language model in
    drishti.py only renders them as a sentence. The cryptographic verdict is
    never produced by a model - that boundary is deliberate.
    """
    component_map = component_map or {"0": "platform firmware", "4": "bootloader/kernel",
                                      "7": "secure-boot policy", "10": "root filesystem (dm-verity)"}
    out = []
    for pcr, exp in expected.items():
        got = actual.get(pcr)
        if got != exp:
            out.append(f"PCR {pcr} ({component_map.get(pcr, 'unknown')}) diverged: "
                       f"expected {exp[:16]}..., measured {got[:16] if got else 'absent'}...")
    return out
