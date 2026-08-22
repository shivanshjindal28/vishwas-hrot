"""VISHWAS Verifier - RATS verifier and appraisal policy engine.

Consumes EAT-style evidence, checks the quote signature, the nonce freshness
and the channel binding, appraises the measurements against the golden
reference database, and issues a signed Attestation Result:

    TRUSTED / DEGRADED / UNTRUSTED, with reasons.

Relying parties (802.1X network admission, the OTA server, application APIs)
consume that result directly. Cryptographic appraisal happens here and only
here - no model output can change the verdict.
"""
from __future__ import annotations

import hmac
import json
import time

from .chhaap import explain_drift
from .mool import sha256

TRUSTED, DEGRADED, UNTRUSTED = "TRUSTED", "DEGRADED", "UNTRUSTED"


class Verifier:
    def __init__(self, golden: dict, freshness_seconds: int = 300):
        self.golden = golden               # expected PCR state per approved build
        self.freshness = freshness_seconds  # trust decay window
        self._issued_nonces: dict[str, float] = {}

    def challenge(self, rot_random) -> bytes:
        n = rot_random(32)
        self._issued_nonces[n.hex()] = time.time()
        return n

    def appraise(self, evidence: dict, expected_channel: bytes, device_rot) -> dict:
        reasons: list[str] = []

        # 1. nonce must be one we issued, and still fresh (trust decay)
        issued = self._issued_nonces.get(evidence["nonce"])
        if issued is None:
            return self._result(evidence, UNTRUSTED, ["unknown nonce - replayed or forged evidence"])
        if time.time() - issued > self.freshness:
            return self._result(evidence, UNTRUSTED, ["attestation expired - freshness window passed"])

        # 2. channel binding: defeats attestation relay / cuckoo attack
        if bytes.fromhex(evidence["tls_exporter"]) != expected_channel:
            return self._result(evidence, UNTRUSTED,
                                ["channel binding mismatch - quote relayed from another host"])

        # 3. quote signature, over nonce||channel
        challenge = sha256(bytes.fromhex(evidence["nonce"]) + expected_channel)
        expect = device_rot.quote([0, 4, 7, 10], challenge)
        if not hmac.compare_digest(expect["sig"], evidence["quote"]["sig"]):
            return self._result(evidence, UNTRUSTED, ["quote signature invalid"])

        # 4. appraise measurements against the golden reference set
        actual = json.loads(evidence["quote"]["body"])["pcrs"]
        drift = explain_drift(self.golden, actual)
        if drift:
            return self._result(evidence, UNTRUSTED, drift)
        return self._result(evidence, TRUSTED, ["all measurements match an approved policy"])

    def _result(self, evidence, status, reasons):
        return {"serial": evidence["idevid"]["serial"], "tier": evidence["idevid"]["tier"],
                "status": status, "reasons": reasons, "expires_in": self.freshness,
                "issued_at": time.time()}
