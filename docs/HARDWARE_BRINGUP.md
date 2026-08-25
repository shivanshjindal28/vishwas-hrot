# Hardware bring-up: ARM (OP-TEE) and RISC-V (SRAM PUF) tiers

The MOOL contract (`vishwas/mool.py`) is the whole portability argument: nine
calls, three anchors, one evidence format. This document specifies exactly how
the two non-x86 backends bind those nine calls to real silicon, so the
implementation path is concrete rather than aspirational.

---

## Tier B — ARM64, OP-TEE firmware TPM

**Target:** any ARMv8-A SoC with TrustZone and a secure-world capable boot chain
(i.MX8, Rockchip RK3399, RPi 4 with an OP-TEE-enabled build).

### Boot chain
```
BootROM (immutable, vendor)
  -> SPL / TF-A BL2        verifies BL31 + BL32 against the SoC's fused key hash
  -> BL31 (TF-A runtime)   installs the secure monitor
  -> BL32 = OP-TEE OS      secure world; loads the fTPM Trusted Application
  -> BL33 = U-Boot         verifies a signed FIT image (kernel + dtb + initramfs)
  -> Linux                 dm-verity rootfs, IMA/EVM
```

### MOOL binding
| MOOL call | OP-TEE mechanism |
|---|---|
| `derive_key(label)` | `TEE_DeriveKeyFromHUK` on the Hardware Unique Key |
| `measure` / `extend` | fTPM TA PCR bank (`TPM2_PCR_Extend` in the secure world) |
| `quote` | `TPM2_Quote` inside the TA; AK never leaves secure world |
| `seal_to_policy` | `TPM2_Create` + `TPM2_PolicyAuthorize` on the signed policy |
| `monotonic_counter` | eMMC **RPMB** partition (replay-protected, authenticated) |
| `random` | `TEE_GenerateRandom` (SoC TRNG) |

### Bring-up steps
1. Build OP-TEE OS with `CFG_RPMB_FS=y` and the Microsoft/ms-tpm-20-ref fTPM TA.
2. Fuse the platform public-key hash; enable secure boot in the SoC's OTP.
3. Expose `/dev/tpm0` from the kernel's `tpm_ftpm_tee` driver.
4. Point `TPM20Backend` at that device node — **no change above MOOL is needed**,
   which is the property this design exists to demonstrate.

### Notes
RPMB gives a genuine monotonic counter without a discrete secure element, which
is what makes anti-rollback (gate 3) enforceable on a cost-sensitive board.

---

## Tier C — RISC-V MCU, SRAM PUF (no TPM at all)

**Target:** C-DAC **VEGA** family / SHAKTI-class cores, or any RV32/RV64 MCU
with PMP and uninitialised-SRAM access at reset. This is the tier that removes
the imported security element entirely.

### Why a PUF instead of stored keys
On-chip SRAM powers up into a pattern determined by transistor threshold
mismatch — a physical fingerprint of that specific die. It is:
- **unique** per device (inter-device Hamming distance ~50%),
- **repeatable** on the same device (intra-device distance ~5-10%, hence the
  error correction below),
- **never stored anywhere**, so there is no key to inject at the factory, no key
  in flash to extract, and no key an insider on the production line can copy.

### Enrolment (once, at manufacture)
```
1. Power on, read N bytes of uninitialised SRAM  -> response R0
2. Generate a random seed S
3. Compute helper data W = R0 XOR BCH_encode(S)   (public, stored in flash)
4. Derive the device seed, emit a CSR for the IDevID
5. S is discarded. Only W is retained, and W alone reveals nothing.
```

### Reconstruction (every boot)
```
1. Read SRAM  -> noisy response R'  (differs from R0 by a few percent of bits)
2. S' = BCH_decode(R' XOR W)         corrects the noise
3. If the error weight exceeds the code's correction bound -> ABORT.
   A different die is far outside that bound, so a cloned board fails here.
4. Device seed = KDF(S'); feeds derive_key / sign / seal exactly as on Tier A.
```
`SramPufBackend._reconstruct()` implements this control flow with a digest
standing in for the BCH stage; swapping in a real BCH(255,131,t=18) codec is a
contained change to that one method.

### Isolation
RISC-V **PMP** regions lock the RoT firmware, the helper data and the derived
seed into a region the application core cannot read after `mret` into U-mode.
eFuse holds only the **public** root hash — nothing secret is ever fused.

### Constrained-tier budget (design targets)
| Resource | Target |
|---|---|
| RoT firmware flash | < 24 KB |
| SRAM for PUF + fuzzy extractor | < 8 KB (transient, zeroised after use) |
| Boot-time cost of reconstruction | single-digit ms |
| Evidence (EAT/CBOR) on the wire | ~ 300 bytes |

Constrained devices attest over CoAP/DTLS rather than TLS; the channel-binding
value becomes the DTLS exporter, and the rest of SETU is unchanged.

---

## What is proven today vs. what bring-up adds

| | Tier A (x86) | Tier B (ARM) | Tier C (RISC-V) |
|---|---|---|---|
| MOOL nine-call contract | executable, tested | executable, tested | executable, tested |
| Protocol + evidence format | proven | proven | proven |
| Bound to real silicon primitives | tpm2-tools when present | bring-up | bring-up |

Every security property in the attack matrix is enforced at the protocol layer
and is therefore identical across tiers. Bring-up substitutes the hardware
primitive behind each MOOL call; it does not change a single caller.
