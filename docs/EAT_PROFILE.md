# VISHWAS EAT profile (draft)

The evidence format every tier emits, intended to be published as an open
specification so Indian devices interoperate while remaining independently
rooted. Follows IETF RFC 9334 (RATS) roles: **Attester** (device),
**Verifier** (appraisal service), **Relying Party** (NAC, OTA, application).

## Claims

| Claim | Type | Meaning |
|---|---|---|
| `serial` | text | Device serial from the IDevID |
| `tier` | text | `desktop` \| `embedded` \| `iot` |
| `ak` | bytes | Attestation key identifier (digest of the public AK) |
| `pcrs` | map | PCR index -> SHA-256 measurement |
| `nonce` | bytes | Verifier-issued challenge (freshness) |
| `chan` | bytes | TLS/DTLS exporter value (channel binding) |
| `evlog` | array | TCG-style event log: stage, PCR index, digest |
| `fwver` | uint | Running firmware version (cross-checked vs. the HRoT counter) |
| `sbom` | bytes | Digest of the running image's SBOM |

`nonce` and `chan` are hashed together and signed **inside** the quote. This is
the anti-relay property: evidence produced for one channel is worthless on
another, which closes the cuckoo attack.

## Attestation Result (Verifier -> Relying Party)

```json
{
  "serial": "VEGA-DEV-0001",
  "tier": "iot",
  "status": "TRUSTED | DEGRADED | UNTRUSTED",
  "reasons": ["all measurements match an approved policy"],
  "expires_in": 300,
  "issued_at": 1756055000.0
}
```

`expires_in` is the **trust-decay** window. A relying party must treat an
expired result as UNTRUSTED and re-challenge; boot-time trust is never
open-ended.

## Encoding

CBOR with a COSE_Sign1 envelope on the wire. The reference implementation uses
canonical JSON for readability during evaluation; the claim set and the signing
input are identical under both encodings.
