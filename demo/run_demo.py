"""End-to-end VISHWAS demo: silicon -> boot -> attest -> update -> re-attest.

Run:  python demo/run_demo.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vishwas.chhaap import BootStage, MeasuredBoot, current_state, policy_digest
from vishwas.drishti import explain, fleet_anomaly
from vishwas.lekha import TransparencyLog
from vishwas.mool import get_rot, sha256
from vishwas.nirantar import Signer, UpdateEngine
from vishwas.setu import DeviceIdentity
from vishwas.verifier import Verifier


def hr(t):
    print("\n" + "=" * 72 + f"\n  {t}\n" + "=" * 72)


def boot_device(tier):
    rot = get_rot(tier)
    mb = MeasuredBoot(rot)
    stages = [BootStage("bootrom->spl", b"spl-image-v1", 0),
              BootStage("bootloader", b"u-boot-fit-v1", 4),
              BootStage("secureboot-policy", b"policy-keys-v1", 7),
              BootStage("kernel+dm-verity", b"kernel-rootfs-v1", 10)]
    for s in stages:
        s.signature = mb.sign_stage(s.image)
    log = mb.boot(stages)
    return rot, mb, log


hr("1. MOOL - same nine-call API on three different trust anchors")
for tier in ("desktop", "embedded", "iot"):
    r = get_rot(tier)
    print(f"  {tier:9s} -> {r.name:26s} attestation key id {r.ak_id()[:16]}...")

hr("2. CHHAAP - verified + measured boot, then policy sealing")
rot, mb, event_log = boot_device("desktop")
for e in event_log:
    print(f"  PCR {e['pcr']:<2} {e['stage']:<20} {e['digest'][:16]}...  verified={e['verified']}")
approved = current_state(rot)
pol = policy_digest({"build": "v1", "state": approved})
sealed = rot.seal_to_policy(b"disk-encryption-key-0123456789ab", pol)
print(f"  sealed disk key to signed policy {pol.hex()[:16]}...")
print(f"  unsealed OK: {rot.unseal(sealed, pol)!r}")

hr("3. SETU + Verifier - attested onboarding with channel binding")
dev = DeviceIdentity(rot, serial="VEGA-DEV-0001")
verifier = Verifier(golden=approved)
nonce = verifier.challenge(rot.random)
channel = os.urandom(32)                      # TLS exporter value
evidence = dev.attest(nonce, channel, event_log)
result = verifier.appraise(evidence, channel, rot)
print(f"  Attestation Result: {result['status']}  ({result['reasons'][0]})")
print("  -> 802.1X admits the device and issues a short-lived LDevID")

hr("4. NIRANTAR + LEKHA - a transparent, post-quantum-hybrid update")
signer = Signer()
pubs = signer.public_bundle(); pubs["_pq_secret"] = signer.pq_seed.hex()
print(f"  signing algorithms: ECDSA-P256 + {signer.pq_alg}")
log = TransparencyLog()
engine = UpdateEngine(rot, pubs)
img = b"kernel-rootfs-v2"
entry = {"name": "kernel-rootfs", "version": 2, "image_hash": sha256(img).hex()}
idx = log.append(entry)
slot = engine.install(img, 2, signer.sign(img), entry, log.inclusion_proof(idx))
print(f"  all four gates passed -> written to slot {slot}, HRoT min version now "
      f"{rot.monotonic_counter()}")

hr("5. DRISHTI - explainable drift and targeted-build detection")
rot2, mb2, log2 = boot_device("desktop")
rot2.extend(4, rot2.measure(b"tampered-bootloader"))
from vishwas.chhaap import explain_drift
print(explain(explain_drift(approved, current_state(rot2)),
              {"shim": "15.8 -> 15.9"}))
fleet = {f"dev-{i}": "measurement-A" for i in range(40)}
fleet.update({f"dev-{i}": "measurement-B" for i in range(40, 42)})
print(f"\n  Fleet anomaly (validly signed but only on a small slice): "
      f"{fleet_anomaly(fleet)}")

print("\nDemo complete. Run `python demo/attacks.py` for the attack matrix.\n")
