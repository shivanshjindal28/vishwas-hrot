"""SETU - hardware-backed device identity and attested onboarding.

The device key is generated inside the trust anchor (or reconstructed from the
SRAM PUF) and never leaves it, so there is nothing for a factory insider to
steal and nothing to clone onto counterfeit hardware.

Attestation is fused into the TLS handshake: the verifier nonce AND the TLS
exporter (channel-binding) value are both signed inside the quote. A
compromised host therefore cannot relay a healthy machine's quote over a
different channel - this closes the cuckoo attack that most attestation
deployments leave open.
"""
from __future__ import annotations

import json

from .mool import RoTBackend, sha256


class IdentityError(Exception):
    pass


class DeviceIdentity:
    """IEEE 802.1AR style identity: long-lived IDevID, short-lived LDevID."""

    def __init__(self, rot: RoTBackend, serial: str):
        self.rot = rot
        self.serial = serial
        # Only a CSR ever leaves the device; the private key stays in silicon.
        self.idevid = {"serial": serial, "tier": rot.tier, "ak": rot.ak_id()}

    def csr(self) -> dict:
        return dict(self.idevid)

    def attest(self, nonce: bytes, tls_exporter: bytes, event_log: list) -> dict:
        """Produce RATS evidence (EAT-style) bound to this exact channel."""
        challenge = sha256(nonce + tls_exporter)
        quote = self.rot.quote([0, 4, 7, 10], challenge)
        return {"idevid": self.idevid, "quote": quote,
                "event_log": event_log,
                "nonce": nonce.hex(), "tls_exporter": tls_exporter.hex()}
