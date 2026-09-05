# Signature Verification Playbook

A practical, offline-first playbook for verifying detached signatures when you cannot (or should not) trust a remote service. Pairs with `examples/verify_detached_sig.py`.

## When to use

- Receiving a signed artifact (release tarball, config bundle, container manifest digest, JSON envelope) from an unfamiliar publisher.
- Auditing historical signatures after a key compromise disclosure.
- Cross-checking what a hosted "verify" endpoint claims against a local, reproducible check.

## Core principles

1. **Verification is local.** The bytes you verify against must come from a channel you already trust (HTTPS with pinned cert, signed transparency log entry, out-of-band hash, etc.). Treat the signature file as untrusted input.
2. **Trust is anchored, not transitive.** A signature is only as good as the key it claims, and the key is only as good as the anchor that vouches for it (cert chain, DID document, transparency log, web of trust introduction).
3. **Algorithm agility is mandatory.** Reject anything pinned to a single algorithm; pin to a *family* (e.g., Ed25519/SHA-512 or ECDSA-P256/SHA-256) and require explicit migration.
4. **Fail closed, loudly.** On *any* anomaly — wrong curve, unexpected hash OID, missing MIME parameters, expired anchor, unsupported critical extension — reject and log.
5. **Reproduce.** If you cannot re-run the verification on a clean machine and get the same answer, you do not have verification; you have theater.

## The 10-step verification flow

| # | Step | What to check | Common failure |
|---|------|---------------|----------------|
| 1 | Fetch artifact | SHA-256 of downloaded bytes matches the value advertised in a second channel | TOFU on attacker-controlled page |
| 2 | Fetch signature | Correct file/payload, correct encoding (binary vs armored vs base64url) | Newline/CRLF mangling in armored text |
| 3 | Identify algorithm | OID / curve name / hash explicitly named; not just "signed" | ECDSA-without-hash, RSA-PKCS1v1.5 without padding check |
| 4 | Fetch anchor | Cert chain or DID doc or trust list; verify chain to a root you already accept | Relying on a root you "just imported" last week |
| 5 | Check anchor status | Not revoked (CRL fresh, OCSP staple valid, or log inclusion proven) | Stale CRLs; missing SCTs for cert transparency |
| 6 | Check key constraints | Usage flags / purpose / method-specific constraints match the artifact type | Email-only cert signing code; non-repudiation missing |
| 7 | Check validity period | Signature creation time inside both signer cert period and root period | Day-boundary edge cases; timezone confusion |
| 8 | Verify cryptographic primitive | Constant-time verify; reject if input rejected for malformed DER/JWT/etc | Trailing bytes accepted; ECDSA point not on curve |
| 9 | Verify binding | Signature is over the *exact* payload you intend to consume (canonical form, not display form) | Whitespace-tolerant canonicalization hiding payload swap |
| 10 | Record decision | Persist: artifact hash, algorithm, anchor fingerprint, verify result, timestamp, verifier version | "We checked it once" with no audit trail |

## Red flags during verification

- **Algorithm downgrades.** A signature that verifies under SHA-1 when SHA-256 was expected is a downgrade attack, not a "compatibility success." Reject.
- **Extra fields.** Unrecognized critical extensions in a CMS/PKCS#7 signature, or extra JWT claims you didn't request, are reasons to stop.
- **Trust chain elasticity.** Adding a cross-cert or bridge CA on the spot to "make it verify" is a smell. Cross-certs require governance, not expedience.
- **Replayed signatures.** Same signature value over a payload that has changed in metadata (timestamps, sequence numbers) means the binding is loose.
- **Non-determinism.** ECDSA and RSA-PSS can be deterministic; if the library produces a different signature each run, you may be seeing a malleability or backdoor concern.

## Algorithm allowlist (baseline)

Start here, prune per your threat model:

- **Preferred:** Ed25519, Ed448, ECDSA-P256/P384/P521 with SHA-256/384/512, RSA-PSS with SHA-256/384/512 and MGF1, ML-DSA (Dilithium) once finalized and broadly supported.
- **Acceptable for legacy interop, not for new trust:** RSA-PKCS#1 v1.5 with SHA-256 (reject any but the shortest valid padding lengths).
- **Refuse:** MD5, SHA-1, RSA-PKCS#1 v1.5 with SHA-1, DSA, ECDSA without explicit hash, any "hash-then-sign" variant where the hash is truncated below 128 bits.

## Common pitfalls in detached-signature tooling

1. **Canonicalization drift between signer and verifier.** Especially in XMLDSig, CMS, and JWT — pick *one* canonicalizer (C14N11, JCS, RFC 8785) and pin it.
2. **Streaming vs buffered hash.** If the tool buffers the whole file to hash it, a 10 GB artifact will OOM. If it streams, double-check it feeds the *exact* bytes into the hash that will be fed to verify.
3. **Trailing-byte tolerance.** Some PEM/CMS parsers silently strip trailing whitespace or BOM; that changes the hash. Disable any auto-trim.
4. **Trust store mixing.** System trust store + bundled CA + policy-defined CA can conflict. Be explicit about precedence.
5. **OCSP/CRL fetch as side effect.** A "verify" call that silently hits the network for revocation is not offline. Either disable and rely on stapled responses / short-lived certs, or make the network step explicit and logged.

## Threat-model cross-reference

- **Key compromise** → see `docs/incident_response_key_compromise.md`; verification steps 5 and 6 are your first line of defense post-disclosure.
- **Algorithm deprecation** → see `docs/sig_algo_agility.md`; the allowlist above is your migration floor.
- **Anchor trust decisions** → see `docs/trust_anchors.md` and `docs/federated_trust_roots.md`.
- **Did-method-specific quirks** (e.g., did:web vs did:key vs did:ion) → see `docs/did_method_evaluation.md`.

## Decision record template

For each verified artifact, record:

```
artifact_sha256: <hex>
sig_alg: <oid or name>
anchor_kind: x509 | did | pgp | ssh | transparency-log
anchor_fingerprint: <hex>
anchor_chain_depth: <int>
revocation_checked: yes | no | n/a
verify_result: pass | fail
verify_tool: <name + version>
verify_time_utc: <RFC3339>
verifier_did: did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX
notes: <free text, max 500 chars>
```

Persisting these records turns ad-hoc verification into an audit trail your future self (or a successor agent) can replay.

## One-liner mental check

> "Am I trusting the bytes, the signature, the key, the anchor, the algorithm, and the verifier — and can I prove each one independently?"

If any of those six is "I just hope so," do not pass the signature onward.

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
