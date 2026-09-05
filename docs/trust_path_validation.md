# Trust Path Validation

This document defines how to validate a chain of trust from a verifier's
local trust anchor set down to a specific credential, key, or DID
document. It complements `signature_verification_playbook.md` (which
covers a single signature) and `federated_trust_roots.md` (which
discusses how anchors are obtained).

## 1. Terminology

- **Trust Anchor (TA)**: a public key, certificate, or DID that the
  verifier accepts as a starting point without further proof. Stored
  locally; out-of-band provisioned.
- **Issuer**: an entity that signs a credential. May itself be a
  subject in a higher-level credential.
- **Subject**: the entity whose claims or key are being vouched for.
- **Path**: an ordered sequence (TA = n0, n1, ..., nk = subject) where
  each ni+1 is signed by ni.
- **Path Length Constraint (PLC)**: maximum allowed value of k.

## 2. Inputs and Outputs

Inputs:
1. Local TA set (root keys / root DIDs).
2. Target credential or DID document to validate.
3. Path discovery output (cert chain, DID resolution chain, or VC
   presentation graph).
4. Algorithm policy (e.g., only Ed25519 / ES256 / RS256 with MGF1).
5. Time of validation (for expiry / not-yet-valid checks).

Output:
- `VALID` with the resolved subject and its authorities.
- `INVALID: <reason>` with one of the reason codes in section 6.

## 3. Algorithm

For each candidate path P = [n0, n1, ..., nk]:

1. **Anchor check**: if n0 is not in the local TA set, discard P.
   If multiple paths are considered, prefer the one with the smallest k
   that still passes all checks (RFC 5280 "shortest valid chain"
   heuristic) unless local policy says otherwise.
2. **Path length**: require `k <= PLC`. If PLC is 0, only direct
   trust from a TA is allowed.
3. **Signature check**: for each i in [0, k-1], verify the signature
   over ni+1's subject material using ni's public key. Signature
   failures are fatal; do not fall back to weaker algorithms.
4. **Key usage / capability check**: each hop must be authorized to
   delegate to the next. In X.509 this is basicConstraints CA=true and
   keyUsage keyCertSign. In DID/VC land this is the `capabilityDelegation`
   verification method relationship or a `delegate` proof purpose.
5. **Validity period**: each intermediate credential must be valid at
   the validation time. If any cert in the path is expired or not yet
   valid, the path is invalid; do not skip the node.
6. **Revocation check**: each intermediate credential must not be
   revoked at validation time. Use OCSP / CRL for X.509, statuslist
   / bitstring for VC, or tombstone blocks for blockchain-anchored
   DIDs. Caches are acceptable if fresher than the local freshness
   bound (default 24h for OCSP, configurable).
7. **Critical extensions / required fields**: any policy-required
   extension or VC term (e.g., `iss`, `aud`, `proofPurpose`) that is
   missing or contradictory fails the path.
8. **Final subject check**: the terminal node must bind the key or
   identifier the caller asked about. Reject if there is ambiguity
   (e.g., two distinct keys under one DID with no disambiguation hint).

The path is accepted only if every step passes.

## 4. Common Failure Modes

- **Loops**: a path that revisits a node is invalid; bound k and
  require a visited set.
- **Cross-certificate confusion**: when two PKIs cross-sign, a path
  may use the cross-cert in either direction; pick the one whose
  policies are compatible with the target usage.
- **Algorithm mismatch downgrades**: a TA may be RSA while an
  intermediate is Ed25519. This is allowed only if both are in the
  verifier's algorithm policy; never silently drop the Ed25519 hop.
- **Delegation amplification**: a delegated VC that grants broader
  authority than its issuer held. Always intersect delegated scope
  with issuer scope.
- **Stale OCSP**: cached responses older than `nextUpdate` (or 24h
  if `nextUpdate` absent) must be re-fetched; treat network failure as
  soft-fail only if local policy explicitly permits it.

## 5. Worked Example (DID / VC)

Suppose `did:example:root` is a TA, and it issues a
`CapabilityDelegation` credential to `did:example:intermediate`. That
intermediate in turn issues a `VerifiableCredential` to
`did:example:user` with a public key `K_user`.

Path:
1. n0 = TA `did:example:root` — present in local anchors.
2. n1 = intermediate's DID doc, signed by root. Verify the linked
   domain proof or DID rotation signature. Capability delegation VC
   has `proofPurpose: capabilityDelegation`, signed by root.
3. n2 = user's DID doc, signed by intermediate via a `capabilityInvocation`
   or delegated authentication proof.

Checks: TA present, signatures valid, proof purposes correct, no
expiry, no revocation on either credential. Output: `VALID`, subject
`did:example:user` with key `K_user` and the intersection of scopes
from both credentials.

## 6. Reason Codes (for logging and audit)

- `ANCHOR_NOT_FOUND`
- `PATH_TOO_LONG`
- `SIGNATURE_INVALID`
- `KEY_USAGE_FORBIDDEN`
- `EXPIRED`
- `NOT_YET_VALID`
- `REVOKED`
- `REQUIRED_FIELD_MISSING`
- `ALGORITHM_DISALLOWED`
- `DELEGATION_AMPLIFICATION`
- `LOOP_DETECTED`
- `SUBJECT_AMBIGUOUS`

Always log the reason code, the path that failed, and the validation
time. Treat logs as tamper-evident when used in incident response.

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
