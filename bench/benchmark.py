"""Measured overhead of the VISHWAS security pipeline.

Reports the cost each security property actually imposes, because a control
nobody can afford to run is a control that gets disabled. Numbers below are
for the software-modelled trust anchor (Tier A reference); discrete-TPM
figures are dominated by the TPM's own command latency and are reported
separately during hardware bring-up.

Run:  python bench/benchmark.py
"""
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vishwas.chhaap import BootStage, MeasuredBoot, current_state, policy_digest
from vishwas.lekha import TransparencyLog, verify_inclusion
from vishwas.mool import get_rot, sha256
from vishwas.nirantar import Signer, UpdateEngine
from vishwas.setu import DeviceIdentity
from vishwas.verifier import Verifier

REPEATS = 200


def bench(label, fn, repeats=REPEATS):
    fn()  # warm up
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    return {"label": label,
            "mean_ms": statistics.mean(samples),
            "p50_ms": samples[len(samples) // 2],
            "p95_ms": samples[int(len(samples) * 0.95)]}


def build_stages(mb):
    stages = [BootStage("spl", b"spl-v1" * 64, 0),
              BootStage("bootloader", b"u-boot-v1" * 512, 4),
              BootStage("policy", b"policy-v1" * 64, 7),
              BootStage("rootfs", b"rootfs-v1" * 4096, 10)]
    for s in stages:
        s.signature = mb.sign_stage(s.image)
    return stages


results = []

# --- 1. boot chain: verify + measure, vs measure-only baseline -------------
rot = get_rot("desktop")
mb = MeasuredBoot(rot)
stages = build_stages(mb)

def full_boot():
    r = get_rot("desktop")
    MeasuredBoot(r).boot(stages)

def measure_only():
    r = get_rot("desktop")
    for s in stages:
        r.extend(s.pcr, r.measure(s.image))

results.append(bench("Boot chain: verify + measure (4 stages)", full_boot))
results.append(bench("Boot chain: measure only (no verification)", measure_only))

# --- 2. policy sealing -----------------------------------------------------
MeasuredBoot(rot).boot(stages)
pol = policy_digest({"build": "v1", "state": current_state(rot)})
sealed = rot.seal_to_policy(b"disk-encryption-key-0123456789ab", pol)
results.append(bench("Seal disk key to signed policy", lambda: rot.seal_to_policy(b"k" * 32, pol)))
results.append(bench("Unseal under matching policy", lambda: rot.unseal(sealed, pol)))

# --- 3. attestation round trip --------------------------------------------
elog = MeasuredBoot(rot).boot(stages)
dev = DeviceIdentity(rot, "BENCH-0001")
verifier = Verifier(golden=current_state(rot))

def attest_roundtrip():
    nonce = verifier.challenge(rot.random)
    ch = os.urandom(32)
    ev = dev.attest(nonce, ch, elog)
    verifier.appraise(ev, ch, rot)

results.append(bench("Attestation round trip (quote + appraise)", attest_roundtrip))

# --- 4. transparency log at fleet scale -----------------------------------
for size in (1_000, 10_000, 100_000):
    log = TransparencyLog()
    entries = [{"n": i, "image_hash": sha256(str(i).encode()).hex()} for i in range(size)]
    for e in entries:
        log.append(e)
    idx = size // 2
    proof = log.inclusion_proof(idx)
    entry = entries[idx]
    results.append(bench(f"LEKHA inclusion proof VERIFY (log of {size:,})",
                         lambda e=entry, p=proof: verify_inclusion(e, p), repeats=100))
    results.append({"label": f"  proof size (log of {size:,})",
                    "mean_ms": None, "p50_ms": None, "p95_ms": None,
                    "note": f"{len(proof['path'])} hashes = {len(proof['path']) * 32} bytes"})

# --- 5. full update transaction, all four gates ---------------------------
signer = Signer()
pubs = signer.public_bundle()
pubs["_pq_secret"] = signer.pq_seed.hex()
log = TransparencyLog()
img = b"kernel-rootfs-v2" * 8192          # 128 KB image
sigs = signer.sign(img)
entry = {"name": "k", "version": 2, "image_hash": sha256(img).hex()}
proof = log.inclusion_proof(log.append(entry))

def full_update():
    r = get_rot("desktop")
    UpdateEngine(r, pubs).install(img, 2, sigs, entry, proof)

results.append(bench("Update: all 4 gates on a 128 KB image", full_update, repeats=100))
results.append(bench("  gate 1 only: hybrid ECDSA + ML-DSA verify",
                     lambda: __import__("vishwas.nirantar", fromlist=["verify_hybrid"])
                     .verify_hybrid(img, sigs, pubs), repeats=100))

# --- report ----------------------------------------------------------------
print("\n  VISHWAS performance profile")
print("  " + "-" * 78)
print(f"  {'Operation':<52}{'mean':>9}{'p95':>9}")
print("  " + "-" * 78)
for r in results:
    if r["mean_ms"] is None:
        print(f"  {r['label']:<52}{r['note']:>18}")
    else:
        print(f"  {r['label']:<52}{r['mean_ms']:>8.3f}ms{r['p95_ms']:>8.3f}ms")
print("  " + "-" * 78)
print("  Verification overhead on the boot chain is the difference between the")
print("  first two rows. Inclusion-proof verification is O(log n): the proof for")
print("  a 100,000-entry log is 17 hashes, so the transparency guarantee costs")
print("  the device well under a millisecond and a fraction of a kilobyte.\n")
