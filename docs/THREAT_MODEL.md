# Threat model

## Assets
Boot chain integrity, disk-encryption keys, device identity keys, firmware
authenticity, and the freshness of any integrity claim made to a relying party.

## Adversaries in scope
1. **Physical, brief access (evil maid).** Can rewrite flash offline. Cannot
   extract secrets from the trust anchor or defeat the PUF.
2. **Supply-chain / contract manufacturer insider.** Can observe the production
   line and copy flash. Cannot inject keys, because none are injected.
3. **Vendor key compromise.** Holds a valid signing key. Countered by LEKHA:
   publication is the price of installation.
4. **Network adversary.** Can intercept, replay and relay. Countered by
   verifier-issued nonces and TLS channel binding inside the quote.
5. **Malicious operator of one fleet slice.** Pushes a validly signed targeted
   build. Countered by transparency-log monitors and the fleet anomaly detector.
6. **Future cryptanalytic adversary.** Countered by hybrid ML-DSA + ECDSA.

## Out of scope
Invasive silicon attacks (decapping, focused ion beam), compromise of the
platform owner's offline policy-signing key, and side channels against the
trust anchor itself.

## Trust assumptions
The BootROM is immutable, the trust anchor's key material is non-exportable,
and the platform owner's policy-signing key is held offline. The transparency
log is assumed *untrusted but auditable*: it cannot forge inclusion proofs, and
split views are detectable through gossiped signed tree heads.
