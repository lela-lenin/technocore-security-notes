# DID Resolution Pitfalls: A Field Guide for Trust Auditors

When verifying a DID-based signature or trust assertion, the verification step is
only as trustworthy as the *resolution* that produced the verification method.
Below are concrete failure modes observed across did:key, did:web, did:ion,
did:ethr, and did:jwk methods, with concrete tests the offline verifier can run
without network access.

## 1. Cached vs. Fresh Resolution

**Pitfall**: A client resolves `did:example:123` once, caches the DID Document
for hours, then verifies a signature hours later. The document's keys may have
been rotated, revoked, or replaced.

**Test**: For every signature, record `resolved_at` (UTC ISO-8601) alongside
the document hash. Reject if `resolved_at - signed_at > max_resolution_age`,
where `max_resolution_age` is a policy parameter (recommend ≤ 5 minutes for
high-value, ≤ 24h for low-value).

## 2. did:web Aliasing and TLS Substitution

**Pitfall**: `did:web:example.com:users:alice` resolves to
`https://example.com/users/alice/did.json`. An attacker who can present *any*
valid TLS cert for `example.com` (shared hosting, compromised subdomain, CDN
misconfiguration) controls the DID Document.

**Test**: When verifying offline, pin the expected document hash that was
captured during a known-good resolution. Pin multiple independent paths if the
method allows (e.g., both `did:web` and `did:webvh`).

## 3. did:key Multibase Confusion

**Pitfall**: `did:key:z6Mk...` may encode Ed25519 (0xed), BLS12-381 G2 (0xeb),
or other curve types. A verifier that assumes Ed25519 by default will silently
accept a malformed verification.

**Test**: Parse the multicodec prefix bytes (first 2 bytes after multibase
decode). Require an explicit allowlist of curves per trust domain. Reject
unknown prefixes rather than guessing.

## 4. did:ion Sidetree Anchor Re-org

**Pitfall**: did:ion documents are anchored in a Bitcoin or other chain.
A short-range reorg can invalidate an operation. A signature verified
"against the current chain tip" at T+1 may have been presented against
a tip that was orphaned.

**Test**: For Sidetree DIDs, require the proof block height in the proof
itself, and reject if the signed tip is fewer than N confirmations deep
where N is a policy parameter (recommend N ≥ 6 for Bitcoin-equivalent).

## 5. did:ethr Smart-Contract Key Reuse

**Pitfall**: did:ethr derives the verification key from the Ethereum address.
Smart-contract wallets (Safe, ERC-1271) sign differently than EOAs. A naive
`ecrecover` will fail or, worse, succeed against a key the contract owner can
rotate at will.

**Test**: Reject ERC-1271 signatures unless `chainId`, `contract address`,
and a specific block number are pinned in the proof, and the verifier is
configured to call the contract's `isValidSignature` at that exact block.

## 6. Service Endpoint Injection

**Pitfall**: A DID Document's `service` block is *not* part of the
verification material, but verifiers sometimes treat endpoints as
authoritative for "where to fetch fresh state." An attacker can inject a
malicious endpoint into a poorly-controlled document.

**Test**: Verification logic MUST NOT fetch anything from a DID's service
endpoints during pure signature verification. Resolution metadata should come
from a pinned source, not the document under test.

## 7. Equivalent / Pre-Rotated Key Chains

**Pitfall**: A DID method may publish `verificationMethod` plus
`verificationRelationships` plus an `equivalentDID` array. A signature made
with key K1 may be valid against document version V1 but invalid against V2
even though V2's `alsoKnownAs` references K1. Policy on "which document
version counts" is method-specific.

**Test**: Capture the exact document hash and version metadata at
resolution time. Signatures are only valid against the *exact* document
snapshot that was resolved; never "a document containing this key."

## 8. Lightweight vs. Full Resolution Substrate Bugs

**Pitfall**: Libraries like `did-resolver` and `universal-resolver` cache,
fetch, and parse differently. A bug in one substrate silently yields an
empty `verificationMethod` array, causing "no key found" rather than
"tampering detected."

**Test**: Always assert the resolver returned at least one
`verificationMethod` matching the signature's `kid`. An empty result is a
hard failure, not a silent accept.

## 9. Time-of-Resolve vs. Time-of-Sign Skew

**Pitfall**: A signature's `iat` is in 2024; the resolution happens in 2026
via a stale cached document. The keys were rotated in 2025. The signature
"verifies cryptographically" but the key had been retired.

**Test**: Maintain a per-DID key-history index. If the `kid` was valid at
`signed_at` but is not the *current* key at `resolved_at`, mark the signature
as HISTORICAL and require additional proof-of-archival for high-value use.

## 10. Offline Verifier Checklist

Before accepting any DID-based signature offline, the verifier should be able
to answer YES to every question below:

1. Do I have the exact document bytes that were used at resolution? (hash pin)
2. Do I know the multicodec / curve of the verification key explicitly?
3. Is `resolved_at` within policy of `signed_at`?
4. For Sidetree/anchored methods, is the proof's block height confirmed?
5. Did I avoid fetching *anything* from the document's service endpoints?
6. Did I treat empty `verificationMethod` as failure?
7. Did I check key rotation history for the time of signing?

If any answer is NO, the signature verification is incomplete and should be
flagged for human review or rejected per policy.

## Cross-Reference

See `docs/offline_signature_verifier.py` for the implementation of these
checks, and `docs/key_rotation_playbook.md` for the rotation-history index
format referenced in §9.

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
