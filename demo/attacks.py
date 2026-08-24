"""Attack matrix - every row is a defence in the submission, demonstrated live.

Run:  python demo/attacks.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vishwas.chhaap import BootFailure, BootStage, MeasuredBoot, current_state, policy_digest
from vishwas.lekha import TransparencyLog
from vishwas.mool import SramPufBackend, get_rot, sha256
from vishwas.nirantar import Signer, UpdateEngine, UpdateRejected
from vishwas.setu import DeviceIdentity
from vishwas.verifier import Verifier

results = []


def case(name, fn):
    try:
        fn()
        results.append((name, "NOT BLOCKED", "-"))
    except Exception as e:
        results.append((name, "BLOCKED", str(e)[:78]))


def clean_boot(rot=None):
    rot = rot or get_rot("desktop")
    mb = MeasuredBoot(rot)
    st = [BootStage("spl", b"spl-v1", 0), BootStage("bootloader", b"u-boot-v1", 4),
          BootStage("policy", b"policy-v1", 7), BootStage("rootfs", b"rootfs-v1", 10)]
    for s in st:
        s.signature = mb.sign_stage(s.image)
    return rot, mb, mb.boot(st), st


# 1. Evil maid: rootfs rewritten offline
def evil_maid():
    rot, mb, _, st = clean_boot()
    tampered = BootStage("rootfs", b"rootfs-v1-TAMPERED", 10, signature=st[3].signature)
    MeasuredBoot(rot).boot([tampered])


# 2. Sealed key must not release under a tampered state
def sealed_key_release():
    rot, mb, _, _ = clean_boot()
    pol = policy_digest({"build": "v1", "state": current_state(rot)})
    blob = rot.seal_to_policy(b"disk-key-aaaaaaaaaaaaaaaaaaaaaa", pol)
    rot.extend(4, rot.measure(b"malicious-module"))
    bad_pol = policy_digest({"build": "v1", "state": current_state(rot)})
    rot.unseal(blob, bad_pol)


# 3. Stolen signing key, image never published to the transparency log
def unpublished_update():
    rot, *_ = clean_boot()
    s = Signer(); pubs = s.public_bundle(); pubs["_pq_secret"] = s.pq_seed.hex()
    UpdateEngine(rot, pubs).install(b"evil-fw", 2, s.sign(b"evil-fw"))


# 4. Rollback to an older but validly signed image
def rollback():
    rot, *_ = clean_boot()
    s = Signer(); pubs = s.public_bundle(); pubs["_pq_secret"] = s.pq_seed.hex()
    eng, log = UpdateEngine(rot, pubs), TransparencyLog()
    for img, ver in ((b"fw-v5", 5), (b"fw-v2", 2)):
        e = {"name": "fw", "version": ver, "image_hash": sha256(img).hex()}
        i = log.append(e)
        eng.install(img, ver, s.sign(img), e, log.inclusion_proof(i))


# 5. Post-quantum signature stripped, classical left intact
def pq_stripped():
    rot, *_ = clean_boot()
    s = Signer(); pubs = s.public_bundle(); pubs["_pq_secret"] = s.pq_seed.hex()
    eng, log = UpdateEngine(rot, pubs), TransparencyLog()
    img = b"fw-v3"
    e = {"name": "fw", "version": 3, "image_hash": sha256(img).hex()}
    i = log.append(e)
    sigs = s.sign(img); sigs.pop("pq")
    eng.install(img, 3, sigs, e, log.inclusion_proof(i))


# 6. Device cloning: full flash image copied to another board
def clone():
    good = b"device-0001-sram-startup-pattern"
    genuine = SramPufBackend(good)
    SramPufBackend(b"cloned-board-different-sram-noise", helper_data=genuine.helper_data)


# 7. Attestation relay (cuckoo): healthy quote replayed over another channel
def cuckoo():
    rot, mb, elog, _ = clean_boot()
    v = Verifier(golden=current_state(rot))
    nonce, healthy_channel = v.challenge(rot.random), os.urandom(32)
    ev = DeviceIdentity(rot, "HEALTHY-0001").attest(nonce, healthy_channel, elog)
    attacker_channel = os.urandom(32)
    r = v.appraise(ev, attacker_channel, rot)          # relayed to a different TLS session
    if r["status"] != "TRUSTED":
        raise PermissionError(r["reasons"][0])


# 8. Replayed / forged nonce
def replay():
    rot, mb, elog, _ = clean_boot()
    v = Verifier(golden=current_state(rot))
    ch = os.urandom(32)
    ev = DeviceIdentity(rot, "DEV-0002").attest(b"\x41" * 32, ch, elog)
    r = v.appraise(ev, ch, rot)
    if r["status"] != "TRUSTED":
        raise PermissionError(r["reasons"][0])


for n, f in [("Evil-maid rootfs tampering", evil_maid),
             ("Sealed key release under tampered state", sealed_key_release),
             ("Stolen signing key, unpublished build", unpublished_update),
             ("Version rollback to signed vulnerable image", rollback),
             ("Post-quantum signature stripped", pq_stripped),
             ("Device cloning / flash copy", clone),
             ("Attestation relay (cuckoo attack)", cuckoo),
             ("Replayed attestation nonce", replay)]:
    case(n, f)

print("\n  VISHWAS attack matrix\n  " + "-" * 96)
print(f"  {'Attack':<45}{'Outcome':<14}Mechanism that stopped it")
print("  " + "-" * 96)
for name, outcome, why in results:
    print(f"  {name:<45}{outcome:<14}{why}")
print("  " + "-" * 96)
blocked = sum(1 for _, o, _ in results if o == "BLOCKED")
print(f"  {blocked}/{len(results)} attacks blocked\n")
sys.exit(0 if blocked == len(results) else 1)
