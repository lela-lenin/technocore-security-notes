# JWS & JCS Canonicalization Audit Notes

Scope: practical checks a verifier can run offline to detect the most common
JSON Web Signature (RFC 7515) and JSON Canonicalization Scheme (RFC 8785)
problems observed in the wild.

## 1. What "canonical" actually means here

A detached JWS over a JSON payload (e.g. a DID operation or VC) is only
authentic if the verifier reconstructs the *exact* byte sequence that was
signed. Two failure modes dominate:

1. The signer used a JSON serializer that reordered keys, escaped Unicode
   (\uXXXX vs. literal UTF-8), or stripped/added whitespace. The signature
   still verifies against the serializer's output but fails against anyone
   else's bytes.
2. The verifier canonicalized, but used a non-RFC 8785 scheme (e.g. JCS-lens
   variants, sorted-keys, strict JSON normalization). Signatures are not
   interoperable across schemes.

Rule of thumb: the signature is over bytes, not over a JSON value. Treat
RFC 8785 as the only acceptable canonicalization for cross-system JWS.

## 2. Offline audit checklist

Run each step with no network access, only the document, the JWS, the
public key, and a JCS implementation.

1. **Recanonicalize.** Using RFC 8785 (sorted keys, no whitespace, numeric
   escapes forbidden unless required, minimal string escaping), produce
   `payload_canonical` from the JSON document.
2. **Recompute the signing input.** `signing_input = ASCII(b64url(header)) ||
   "." || ASCII(b64url(payload))`. For *detached* JWS, the payload segment
   in the JWS is empty; substitute `b64url(payload_canonical)` locally.
3. **Verify the signature** over `signing_input` with the declared alg.
   Reject immediately if:
   - alg is `none`,
   - alg is HS* with a public key (algorithm confusion),
   - alg is RS*/PS* but the key is EC (or vice versa),
   - the JWS header contains `kid` but no trusted key resolves to it,
   - `crit` parameters are present and not understood.
4. **Compare.** If verification passes, hash `payload_canonical` and the
   decoded payload from the JWS; they MUST match. If they don't, the
   producer canonicalized differently — do not trust.
5. **Replay & context checks.** Confirm `iat`/`exp`/`nbf` (if present) are
   sane for your wall clock and that any `nonce` or `jti` has not been seen
   before (local cache).

## 3. Common defects to flag

| Defect | Symptom | Detection |
|---|---|---|
| Unicode escape drift | sig verifies on producer, fails here | compare UTF-8 byte length to escaped form length |
| Key reordering | hash differs after recanonicalize | diff sorted vs. document key order |
| Float precision loss | numeric value changed | re-parse and string-compare originals |
| Nested JCS not applied | signature valid only over outer doc | re-run canonicalization on every embedded object |
| Trailing whitespace | sig invalid | strip, re-canonicalize, retry |
| Base64url padding | decoder rejects | accept unpadded per RFC 7515 §2 |

## 4. Worked example (pseudo-run)

Input document:
```json
{"b":2,"a":1,"msg":"héllo"}
```
RFC 8785 canonical form:
```json
{"a":1,"b":2,"msg":"héllo"}
```
Note: "héllo" stays as literal UTF-8 bytes `68 C3 A9 6C 6C 6F`, *not*
`\u00e9`. A producer that emits `\u00e9` produces a different byte string
and its signature will not verify against the literal form.

## 6. Companion code

The repository's `docs/offline_signature_verifier.py` already implements
JCS canonicalization (RFC 8785) plus detached-JWS verification using only
the Python standard library and `cryptography`. Pair this audit doc with
that file when reviewing third-party issuers.

## 7. Reporting template

When filing a finding against an issuer, include:

- SHA-256 of the original document bytes,
- SHA-256 of the RFC 8785 canonical bytes,
- the JWS header (decoded),
- the alg and kid used,
- whether step 4 matched,
- a minimal repro JSON.

This gives any other auditor enough to reproduce offline.

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
