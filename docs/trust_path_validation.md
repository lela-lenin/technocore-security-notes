# Trust Path Validation for Decentralized Identifiers

## Purpose

This note complements `signature_verification_playbook.md` and `federated_trust_roots.md` by giving concrete, procedural guidance on how to *walk* a trust path from an unknown leaf DID to a root that a verifier is willing to trust. A signature verifier only proves that the signer controls a specific key; trust path validation proves that the signer is *also* the entity it claims to be, recursively, up to a trust anchor.

The examples use `did:key` (simple, no resolver needed) and `did:web` (resolves to a DID document at `https://<host>/.well-known/did.json`). Both formats are widely deployed and have well-defined verification procedures in the DID Core spec (W3C, 2022).

## Definitions

- **Trust anchor**: A root key or root certificate a verifier accepts a priori, without further proof.
- **Trust path**: An ordered list of cryptographic attestations (signatures, certifications, delegations) connecting the leaf DID to a trust anchor.
- **Path validation**: The procedure of constructing and verifying a chain such that every link is valid under the constraints defined by the anchors in the chain.
- **Path length constraint**: The maximum number of intermediate authorities permitted between leaf and root. A shorter bound reduces flexibility but shrinks the attack surface for path-substitution attacks.

## Path Construction Procedure

1. **Resolve the leaf DID document.** Fetch the DID Doc for the asserting party and identify its verification methods. For `did:key`, the verification method is derived from the DID itself. For `did:web`, perform an HTTPS GET on the well-known endpoint and validate the TLS certificate chain against your system trust store.
2. **Identify the proof type.** Determine what attestation links this DID to a parent (e.g., a `verificationRelationship` method signed by a parent DID, an x.509 cert issued by a parent CA, a Sidetree operation, or a JWS produced by the parent over the child's DID Doc).
3. **Recurse on the parent.** Repeat from step 1 with the parent's DID. Terminate when you reach either:
   - a DID whose verification method matches a configured trust anchor, or
   - a self-signed root (acceptable only if pre-configured).
4. **Apply constraints.** Reject the path if:
   - any link's signature fails to verify,
   - the chain length exceeds the configured maximum,
   - any intermediate was revoked (checked via CRL/OCSP/Revocation registry),
   - any intermediate's key was used outside its declared `validUntil`/`notAfter`,
   - name constraints or policy constraints are violated (e.g., a `did:web:example.com` issuer claiming authority over `did:web:evil.example.org`).
5. **Bind to context.** A trust path by itself is not a complete authorization decision; bind the result to the operation being authorized (issuing a credential, accessing a resource, signing a message). Path validation must be repeated for each new context; cached trust decisions must carry an expiry.

## Worked Example: did:key leaf signed by did:web issuer

Scenario: a verifier holds trust anchor `did:key:z6Mki...ROOT`. It receives a presentation from leaf `did:key:z6Mkj...LEAF`. The leaf's DID Doc contains a `verificationMethod` referencing the leaf's own key, plus an `assertionMethod` relationship. However, the leaf's DID Doc was signed (via detached JWS) by `did:web:issuer.example.com`. To validate the path:

1. Fetch `https://issuer.example.com/.well-known/did.json` over TLS. Validate TLS chain to a trusted CA.
2. Verify the JWS over the leaf DID Doc using issuer's `assertionMethod` key. Check JWS header `alg` against your algorithm allow-list (see `sig_algo_agility.md`). Reject `none`, `HS*`, and any RS/PS variant with <2048-bit modulus.
3. Confirm the issuer's DID Doc is itself signed or attested by `did:key:z6Mki...ROOT` (e.g., via an `alsoKnownAs` + cross-certification JWS, or because the issuer's verification method equals the root, or the root appears as a trusted parent in a local registry).
4. Check policy: does the root authorize `issuer.example.com` to mint credentials in this namespace? If the root carries a published registry of authorized issuers, look up `issuer.example.com` and confirm the entry is not revoked.
5. Compute and cache the path: `[LEAF -> issuer.example.com -> ROOT]`, length 2, valid for the JWS expiry.

## Common Failure Modes

- **Permissive resolvers**: a resolver that returns *some* DID Doc without verifying the response (e.g., HTTP-only `did:web`, or `did:dns` without DNSSEC) lets an attacker substitute their own document. Always require signed or transport-authenticated resolution.
- **Path substitution**: a verifier that accepts the *shortest* path or *any* valid path can be tricked by an attacker who controls a different branch of the graph. Require a specific policy binding (e.g., "issuance must be via the issuer registered for namespace X") rather than "any valid path to root".
- **Revocation blindness**: a valid chain to a non-revoked root is still invalid if any intermediate was revoked after signing. CRL/OCSP/registry freshness is part of path validation, not a separate step.
- **Algorithm agility drift**: a path built with Ed25519 may become unverifiable after a verifier upgrades to forbid a deprecated algorithm used by an intermediate. Carry algorithm metadata with each link and reject early at construction time.
- **Replay across contexts**: a trust path proven for "read access" does not imply "write access" or "credential issuance". Bind paths to operations at validation time, not at issue time.

## Verification Hook (sketch)

The offline verifier in `docs/offline_signature_verifier.py` is intentionally limited to one-link checks. Path validation cannot be offline-only; it requires at least one of: a local copy of trust anchors, a CRL/OCSP responder, or an online resolver. Recommended layering:

1. **Offline**: verify each individual signature with `offline_signature_verifier.py`.
2. **Online (issuer resolution)**: fetch issuer DID Docs via TLS-authenticated HTTPS.
3. **Online (revocation)**: query CRLs or the method-specific revocation registry.
4. **Local (policy)**: apply name/path-length/algorithm constraints from configuration.

A complete reference implementation should chain these layers in that order, fail closed if any layer is unavailable, and log each link's verification result so a path can be audited after the fact.

## See Also

- `docs/signature_verification_playbook.md` — single-signature verification.
- `docs/federated_trust_roots.md` — how trust anchors are chosen and rotated.
- `docs/sig_algo_agility.md` — algorithm allow-lists for verification.
- `docs/did_method_evaluation.md` — method-specific resolution and revocation behavior.

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
