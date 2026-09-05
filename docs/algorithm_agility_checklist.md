# Algorithm Agility Checklist for Signature Verifiers

A practical, code-review oriented checklist for ensuring a signature verifier can
survive a cryptographic algorithm deprecation or compromise without an emergency
rewrite. Pairs with `docs/sig_algo_agility.md` and `examples/verify_detached_sig.py`.

## 1. Identifier handling

- [ ] Every accepted signature carries an explicit algorithm identifier
      (e.g. JWA alg, OID, or DID method-specific tag). No implicit "default".
- [ ] The identifier is parsed into a structured value (string + params),
      never compared as an opaque blob after a single `==`.
- [ ] Algorithm identifiers are matched against an internal allowlist, not
      a denylist. Denylists always lag behind reality.
- [ ] Unknown / unrecognized identifiers fail closed with a typed error
      (`UnsupportedAlgorithm`), distinct from `InvalidSignature`.
- [ ] Casing, whitespace, and parameter ordering are normalized before
      comparison. No `alg == "ES256"` vs `alg == "es256"` surprises.

## 2. Parameter negotiation

- [ ] If the verifier supports multiple algorithms, the *verifier* chooses
      the acceptable set; the signer's preference is treated as a hint, not
      an order. Never let a caller pick the algorithm by sending a payload.
- [ ] Required parameters (curve, hash, key length) are validated alongside
      the algorithm id. `ES256` with a P-521 key is a misconfiguration.
- [ ] Composite / hybrid constructions (e.g. ML-DSA + Ed25519) carry a
      *combined* identifier, not two independent ones. Partial-verify must
      be impossible.
- [ ] Parameter changes that weaken security (e.g. switching hash from
      SHA-256 to SHA-1) are rejected even if the algorithm id is unchanged.

## 3. Key material binding

- [ ] The algorithm used to sign is checked against the key's declared
      algorithm / curve / type. A `kty=EC, crv=P-256` key may not produce
      an RSA signature even if the math happens to parse.
- [ ] For KEM / hybrid signatures, the encapsulated key is bound to the
      signature context (e.g. included in the transcript hash) so it
      cannot be swapped.
- [ ] Keys carry a `notBefore` / `notAfter` / `revokedAt` lifecycle that is
      evaluated *before* cryptographic checks, with the result logged.

## 4. State and side channels

- [ ] Verification time is roughly constant across the allowlisted
      algorithms. Branching on `alg` to take a fast path is a timing leak
      and a footgun during migration.
- [ ] Error messages do not distinguish "wrong algorithm" from
      "malformed signature" from "wrong key" when the response is
      observable to an attacker. Collapse to a single generic failure.
- [ ] Randomness is never derived from the algorithm choice. No "we'll
      just use a different nonce source for the new curve" surprises.

## 5. Rollout mechanics

- [ ] Algorithm support is config-driven, not code-conditional. A new
      algorithm ships as a config change, not a redeploy.
- [ ] Each supported algorithm has a documented `introduced`, `deprecated`,
      and `sunset` date in the allowlist source file.
- [ ] Deprecation is staged: accept+verify -> accept+warn -> reject, with
      each stage gated by date, not by hand.
- [ ] A rollback path exists: removing an algorithm from the allowlist
      must not require code changes (config revert only).
- [ ] Telemetry counts signatures by algorithm id so you can see the
      long tail before you cut it off.

## 6. Post-quantum readiness

- [ ] Classical and PQC algorithms are verified through *separate*
      pipelines with separate allowlists. A "hybrid" string must name both.
- [ ] The verifier does not assume PQC signatures are larger, slower, or
      have the same encoding as classical ones. No hardcoded 64-byte
      signature buffers.
- [ ] If you support hash-based signatures (SLH-DSA / XMSS), state is a
      first-class concept: remaining signatures, index monotonicity, and
      state persistence are verified, not just the math.
- [ ] Migration plan exists from current classical allowlist to a
      hybrid-first allowlist, with concrete dates and an owner.

## 7. Test surface

- [ ] Conformance vectors for every algorithm in the allowlist live in
      `tests/vectors/` and are run on every CI build.
- [ ] Negative vectors exist for: wrong algorithm, swapped algorithm,
      downgraded parameters, truncated signature, extra trailing bytes,
      and identifier casing attacks.
- [ ] Fuzzing harness feeds random bytes into the verifier entry point
      and asserts it never returns `valid=true` without a matching vector.
- [ ] Cross-implementation interoperability test (e.g. against a second
      library) is part of release gating, not a one-off.

## 8. Incident hooks

- [ ] On `UnsupportedAlgorithm`, the verifier emits a structured log event
      with the rejected id, the peer's identifier (if known), and a
      timestamp. This is your early-warning for a downgrade attempt.
- [ ] On any cryptographic primitive failure, the verifier increments a
      per-algorithm counter exposed via metrics. Spikes are alertable.
- [ ] The allowlist file path and loaded digest are logged at startup so
      a tampered config is detectable after the fact.

## Quick self-audit

For each algorithm in your allowlist, answer in writing:

1. What standard specifies it, and what is the most recent revision?
2. What is the smallest key/signature size you actually accept?
3. What is the *known* quantum security level, and is that acceptable for
   the data being signed for the next N years?
4. Who maintains the reference implementation, and what is their
   disclosure process?
5. On what date will this algorithm be removed from the allowlist, and
   what is the trigger that decides that date?

If any answer is "we'll look it up", you don't have agility, you have
hope.

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
