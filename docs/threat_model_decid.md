# Threat Model for did:key Self-Sovereign Identifiers

This note catalogs the realistic threats to `did:key` DIDs, the assumptions that
must hold for them to be safe to use, and concrete mitigations an integrator can
apply. It complements `did_method_evaluation.md` (which compares DID methods) and
`sig_algo_agility.md` (algorithm posture) by zooming in on the threat surface
that `did:key` actually exposes when used as a trust root.

## 1. What a did:key actually is

`did:key` is defined in the did-method-spec. A DID is the multibase prefix `z`
followed by the multibase-encoded multicodec-prefixed public key bytes. There is
no external registry, no resolver infrastructure, and no revocation mechanism.
The identifier *is* the key.

Example:

```
did:key:z6MkiTb6DNXj7g2MsG4J9cZ6c4F3s7N8oL8K9j2H1bA3dE4fG
```

Anyone who sees the DID can extract the public key locally; no network lookup
is required to verify a signature.

## 2. Trust assumptions

For a `did:key` to function as a trust root, all of the following must hold:

- The verifier received the DID over an *authentic channel*. Because there is
  no registry binding a DID to a subject, the only binding is the one
  established at first contact.
- The holder actually controls the corresponding private key.
- The verification algorithm and parameters used by the verifier match those
  used by the issuer, and neither has been broken.
- Key compromise has not occurred (there is no built-in mechanism to detect
  or signal compromise).

## 3. Threat catalog

### T1. First-contact spoofing (HIGH)

Attacker substitutes their own DID for the legitimate subject's DID during
initial exchange (email, QR code, NFC, etc.). The verifier pins an attacker's
public key and trusts everything signed by it thereafter.

Mitigations:
- Use an out-of-band verification step on first contact (voice call, video,
  signed business card, in-person exchange).
- Prefer DID methods with verifiable binding to a subject identifier when
  long-term trust is required.
- Treat the first use of a `did:key` as low-trust; escalate trust only after a
  second independent channel corroborates.

### T2. Private key compromise (HIGH)

Loss, theft, or extraction of the private key yields total impersonation with
no way to revoke. `did:key` provides no rotation signal.

Mitigations:
- Store keys in hardware-backed keystores (TPM, Secure Enclave, YubiHSM2,
  Android StrongBox).
- Enforce short-lived signatures with freshness tokens (nonce/timestamp
  challenges) so replay windows are bounded.
- Pair `did:key` with a `did:web` or other revokable DID that delegates the
  trust assertion; treat `did:key` as a *capability token*, not as identity.

### T3. Algorithm breakage (MEDIUM)

A `did:key` encodes the multicodec of the algorithm (Ed25519 = `0xed`,
secp256k1 = `0xe7`, BLS12-381-G1 = `0xea`, P-256 = `0x1200`). If that
algorithm is later broken (e.g., Shor's against ECDSA on a CRQC), every DID
encoded with it becomes untrustworthy and cannot be "migrated" — the DID
itself is the algorithm pointer.

Mitigations:
- Prefer Ed25519 today; it is compact, fast, and has no known structural
  weaknesses. Avoid secp256k1 unless Bitcoin/Ethereum compatibility is
  required, and avoid RSA entirely.
- Plan for rotation: when an algorithm weakens, rotate the *subject* to a new
  DID with a different algorithm. This is operationally painful; budget for it.
- See `sig_algo_agility.md` for the broader algorithm-agility posture.

### T4. Multiplicity / squatting (LOW)

Because the keyspace is large but the address space is shorter than a hash, an
attacker cannot squat an existing DID but *can* generate collisions with
*expected* future DIDs if the holder's key generation is biased.

Mitigations:
- Use a vetted library (libsodium, BouncyCastle, NSS, WebCrypto) — do not
  roll your own key generation.
- Verify that the library applies RFC 6979-style determinism *or* uses an
  honest CSPRNG, and that the resulting public key is on-curve.

### T5. Replay of signed assertions (MEDIUM)

`did:key` provides no freshness. A signature captured at t=0 may be replayed at
t=infinity if the verifier does not enforce context, nonce, or expiry.

Mitigations:
- Wrap every signed payload in a JWS with `exp`, `nbf`, and `jti` claims.
- For challenge-response, bind a server-issued nonce into the signed material
  and reject any signature whose nonce is not the most recent issued.
- See `signature_verification_playbook.md` for the canonical envelope.

### T6. Substitution across algorithms (LOW)

A naive verifier that accepts multiple algorithms and parses by multibase
prefix can be tricked into accepting a signature under a weaker algorithm if
the DID prefix is parsed ambiguously.

Mitigations:
- Pin the expected algorithm at the application layer; do not auto-accept
  whichever multibase prefix appears.
- Reject the request if the algorithm multicodec is not in a configured
  allow-list.

### T7. Loss of the private key = loss of identity (HIGH, structural)

This is not an attack but a *failure mode*: there is no recovery mechanism.
The user is the key. Losing it loses the DID permanently, with no recovery
flow, no social recovery, and no support channel.

Mitigations:
- Encourage users to maintain encrypted, geographically distributed backups.
- Architect the system so loss of one `did:key` does not erase the user's
  ability to obtain and prove control of a *new* identity (i.e., do not make
  `did:key` the only pointer to critical state).

## 4. Decision checklist

Use `did:key` when:
- Trust is established out-of-band and the DID is short-lived or scoped.
- You need a credential that resolves fully offline.
- You are issuing a *capability* (a verifiable token) rather than asserting
  a long-lived identity.

Do NOT use `did:key` as the sole root of trust when:
- The subject needs account recovery.
- Revocation is a requirement.
- The relationship must survive algorithm deprecation.
- First-contact authenticity cannot be guaranteed.

## 5. Cross-references

- `did_method_evaluation.md` — comparative method analysis.
- `sig_algo_agility.md` — algorithm posture and migration planning.
- `signature_verification_playbook.md` — canonical verification envelope.
- `key_rotation_playbook.md` — operational rotation procedures.
- `trust_anchor_hygiene.md` — how to bind a DID to a subject securely.
- `offline_signature_verifier.py` — reference implementation that enforces
  algorithm pinning and freshness.

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
