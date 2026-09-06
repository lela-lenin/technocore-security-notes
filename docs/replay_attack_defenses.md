# Replay Attack Defenses for Decentralized Identifiers

## Purpose

Replay attacks present a persistent threat to DID-based authentication, signing,
and key-rotation flows. This document consolidates practical, implementable
defenses that an integrator can apply today, with concrete validation steps
that an offline verifier can perform. It complements the existing notes on
algorithm agility, JWS/JCS canonicalization, and trust-anchor hygiene by
focusing specifically on *time* and *uniqueness* as security controls.

## Threat Recap

A replay attack reuses a previously valid message — a verifiable credential, a
key-update event, a signed DID operation — to trick a verifier into accepting
it as fresh. Even with strong cryptography, absence of freshness or uniqueness
guarantees leaves the door open.

Three common variants:

1. **Pure replay**: attacker captures message `M` and resends it unchanged.
2. **Stripped-replay**: attacker rewraps `M` in a new envelope without
   modifying the signature-protected payload.
3. **Cross-context replay**: attacker takes a token valid in service `A` and
   presents it to service `B`.

## Defense Layers

### 1. Timestamps and Clock Skew Windows

Every signed payload SHOULD include an issuance timestamp (`iat`-equivalent)
and, where applicable, an expiration (`exp`-equivalent). Verifiers MUST:

- Reject messages whose `exp` is in the past relative to verifier clock.
- Reject messages whose `iat` is more than a configured window in the past
  (typical default: 5 minutes for online verifiers, 24 hours for batch).
- Reject messages whose `iat` is in the future beyond a small skew allowance
  (recommended: 60 seconds, to absorb NTP jitter without becoming a knob an
  attacker can exploit).

Do NOT rely on the verifier's wall clock alone for long-lived artifacts.
Combine with the next two layers.

### 2. Nonces

A nonce is a single-use, unpredictable value bound into the signed payload.
Effective when:

- The nonce has at least 128 bits of entropy from a CSPRNG.
- The verifier tracks a nonce store (DB, Redis, in-memory LRU with TTL) and
  rejects duplicates within the validity window.
- The nonce source is authenticated (e.g., server-issued, or a hash chain
  commit-reveal sequence).

For DID operations specifically, prefer protocol-level sequence numbers over
ad-hoc nonces — see Layer 4.

### 3. JTI / Transaction Identifiers

For JOSE-style envelopes, every signed JWT or VC MUST have a unique `jti`
(JWT ID) — equivalent to the W3C VC `id` field — that the verifier logs and
deduplicates. Treat the `jti` as a soft nonce: even if the underlying
signature is valid, a repeated `jti` inside the validity window MUST be
rejected.

Recommended storage:

```
key:   jti (string, ≤ 256 chars)
value: first_seen_unix_seconds
ttl:   max(remaining exp validity, 24h)
```

### 4. Sequence Numbers for DID Operations

Sidetree-based DID methods and similar CAS-only protocols eliminate replay by
construction: every operation references a monotonically increasing
`operationNumber` or equivalent counter. Verifiers MUST:

- Reject operations whose counter is ≤ the last accepted counter for that DID.
- Verify the counter is signed by a key that was authoritative at the
  preceding counter value (chain of custody).

This is the strongest defense available; where the DID method supports it,
prefer it.

### 5. Channel Binding

Bind the signature to the transport context — TLS exporter, DIDComm
`from`/`to` thread-id, or a request-id header — by including the context
hash inside the signed payload. Defeats cross-context replay and supports
audit correlation.

### 6. Revocation and Status Lists

A fresh signature on a credential that has since been revoked MUST be
rejected regardless of timestamps. Check the appropriate status list
(bitstring status list, revocation list, accumulator) at verification time,
and treat any positive revocation hit as authoritative.

## Offline Verifier Behavior

The standalone offline verifier (`docs/offline_signature_verifier.py`) cannot
consult a nonce store, but it CAN and SHOULD enforce:

- `exp` check against the operator-provided reference time.
- `iat` skew check (±300 seconds is a reasonable default for offline use).
- `jti` deduplication against a caller-supplied list of seen identifiers
  (the offline equivalent of a nonce store).
- Sequence-number monotonicity for any DID operation payload that carries one.

A patch outline:

```python
def verify_envelope(env, ref_time, seen_jtis, last_op_num=None):
    payload = verify_signature(env)  # existing path
    if payload.get("exp", 0) < ref_time:
        raise ReplayError("expired")
    iat = payload.get("iat", 0)
    if abs(ref_time - iat) > 300:
        raise ReplayError("iat_skew")
    jti = payload.get("jti")
    if jti is None:
        raise ReplayError("missing_jti")
    if jti in seen_jtis:
        raise ReplayError("replayed_jti")
    if "operationNumber" in payload:
        opn = payload["operationNumber"]
        if last_op_num is not None and opn <= last_op_num:
            raise ReplayError("stale_operation")
    return payload
```

## Operational Checklist

- [ ] All signed envelopes include `iat` and `exp`.
- [ ] All signed envelopes include a unique `jti` (or method-equivalent id).
- [ ] Verifier enforces skew window and rejects future-dated `iat`.
- [ ] Nonce / `jti` store has TTL ≥ max validity window.
- [ ] DID operations are checked for monotonic sequence numbers.
- [ ] Channel binding is present where the transport is meaningful.
- [ ] Revocation status is consulted at verify time, not at issuance time.
- [ ] Logging includes `jti` and timestamp so post-incident analysis can spot
      replay attempts that bypassed the verifier.

## Test Vectors

Good. Three minimal vectors for the offline verifier:

1. **Valid**: `iat = now`, `exp = now + 60`, fresh `jti` → accept.
2. **Expired**: `exp = now - 1` → reject with `ReplayError("expired")`.
3. **Replayed**: same `jti` as previously seen → reject with
   `ReplayError("replayed_jti")`.

## Cross-References

- `docs/offline_signature_verifier.py` — verifier that should enforce these
  checks.
- `docs/jws_jcs_canonicalization_audit.md` — canonicalization affects how
  timestamps and ids are bound into the signature input.
- `docs/algorithm_agility_checklist.md` — algorithm choice (e.g., Ed25519
  vs. ECDSA) does not substitute for freshness controls; do not skip this
  layer because the signature suite is "strong".
- `docs/key_rotation_playbook.md` — rotation events are themselves signed
  operations and therefore subject to replay; verify the rotation operation's
  sequence number.

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
