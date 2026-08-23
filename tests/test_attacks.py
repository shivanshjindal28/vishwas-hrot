"""Negative tests: every defence claimed in the submission has a test."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vishwas.chhaap import BootFailure, BootStage, MeasuredBoot, current_state, policy_digest
from vishwas.lekha import TransparencyLog, verify_inclusion
from vishwas.mool import SramPufBackend, get_rot, sha256
from vishwas.nirantar import Signer, UpdateEngine, UpdateRejected
from vishwas.setu import DeviceIdentity
from vishwas.verifier import Verifier


def booted(tier="desktop"):
    rot = get_rot(tier)
    mb = MeasuredBoot(rot)
    stages = [BootStage("spl", b"spl-v1", 0), BootStage("bl", b"u-boot-v1", 4),
              BootStage("pol", b"policy-v1", 7), BootStage("rootfs", b"rootfs-v1", 10)]
    for s in stages:
        s.signature = mb.sign_stage(s.image)
    return rot, mb, mb.boot(stages)


def signer_engine(rot):
    s = Signer()
    pubs = s.public_bundle()
    pubs["_pq_secret"] = s.pq_seed.hex()
    return s, UpdateEngine(rot, pubs), TransparencyLog()


@pytest.mark.parametrize("tier", ["desktop", "embedded", "iot"])
def test_all_tiers_expose_the_same_contract(tier):
    rot = get_rot(tier)
    q = rot.quote([0, 4], b"nonce")
    assert set(q) == {"body", "sig"}
    assert rot.monotonic_counter() == 0


def test_unsigned_stage_halts_boot():
    rot, mb, _ = booted()
    with pytest.raises(BootFailure):
        MeasuredBoot(rot).boot([BootStage("evil", b"evil", 4, signature=b"\x00" * 32)])


def test_sealing_survives_an_approved_update_but_not_tampering():
    rot, mb, _ = booted()
    pol = policy_digest({"build": "v1", "state": current_state(rot)})
    blob = rot.seal_to_policy(b"k" * 32, pol)
    assert rot.unseal(blob, pol) == b"k" * 32
    rot.extend(4, rot.measure(b"tamper"))
    bad = policy_digest({"build": "v1", "state": current_state(rot)})
    with pytest.raises(PermissionError):
        rot.unseal(blob, bad)


def test_update_requires_transparency_log_proof():
    rot, _, _ = booted()
    s, eng, _ = signer_engine(rot)
    with pytest.raises(UpdateRejected, match="gate 2"):
        eng.install(b"fw", 2, s.sign(b"fw"))


def test_forged_inclusion_proof_rejected():
    log = TransparencyLog()
    entries = [{"n": i} for i in range(5)]
    for e in entries:
        log.append(e)
    proof = log.inclusion_proof(2)
    assert verify_inclusion(entries[2], proof)
    assert not verify_inclusion({"n": 99}, proof)


def test_rollback_blocked_by_monotonic_counter():
    rot, _, _ = booted()
    s, eng, log = signer_engine(rot)
    for img, ver in ((b"v5", 5), (b"v2", 2)):
        e = {"image_hash": sha256(img).hex(), "version": ver}
        i = log.append(e)
        if ver == 5:
            eng.install(img, ver, s.sign(img), e, log.inclusion_proof(i))
        else:
            with pytest.raises(UpdateRejected, match="gate 3"):
                eng.install(img, ver, s.sign(img), e, log.inclusion_proof(i))


def test_hybrid_signature_requires_both_algorithms():
    rot, _, _ = booted()
    s, eng, log = signer_engine(rot)
    img = b"fw-v3"
    e = {"image_hash": sha256(img).hex(), "version": 3}
    i = log.append(e)
    for drop in ("pq", "ec"):
        sigs = s.sign(img)
        sigs.pop(drop)
        with pytest.raises(UpdateRejected, match="gate 1"):
            eng.install(img, 3, sigs, e, log.inclusion_proof(i))


def test_puf_rejects_a_cloned_board():
    genuine = SramPufBackend(b"device-0001-sram-startup-pattern")
    with pytest.raises(PermissionError):
        SramPufBackend(b"cloned-board-noise", helper_data=genuine.helper_data)


def test_cuckoo_relay_rejected_by_channel_binding():
    rot, _, elog = booted()
    v = Verifier(golden=current_state(rot))
    nonce, healthy = v.challenge(rot.random), os.urandom(32)
    ev = DeviceIdentity(rot, "D1").attest(nonce, healthy, elog)
    assert v.appraise(ev, healthy, rot)["status"] == "TRUSTED"
    assert v.appraise(ev, os.urandom(32), rot)["status"] == "UNTRUSTED"


def test_expired_attestation_is_untrusted():
    rot, _, elog = booted()
    v = Verifier(golden=current_state(rot), freshness_seconds=0)
    ch = os.urandom(32)
    ev = DeviceIdentity(rot, "D2").attest(v.challenge(rot.random), ch, elog)
    import time
    time.sleep(0.01)
    assert v.appraise(ev, ch, rot)["status"] == "UNTRUSTED"
