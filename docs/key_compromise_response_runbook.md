# Key Compromise Response Runbook

A concrete, opinionated procedure for responding to a suspected or confirmed
compromise of a private key used to sign messages, attestations, or documents
in the technocore ecosystem. Aligned with the project's signature verification
playbook and algorithm agility checklist.

## 1. Scope and severity tiers

Decide severity before you act; the actions below scale with it.

| Tier | Trigger examples | Time-to-publish revocation |
|------|------------------|----------------------------|
| SEV-1 | Active exfiltration, ongoing fraud, attacker publishing valid sigs | <= 15 minutes |
| SEV-2 | Lost device, suspected leak, post-quarantine malware finding | <= 4 hours |
| SEV-3 | Decommissioned key found online, weak storage, audit finding | <= 1 business day |

When in doubt, escalate one tier. False positives cost little; missed
SEV-1 events cost everything.

## 2. Immediate containment (first 10 minutes)

1. Stop signing. Disable the credential at the issuance point (CI, signing
   service, vault token). Revoke any short-lived bearer tokens derived from it.
2. Snapshot evidence. Capture: last known-good signed artifact with timestamp,
   the suspected exposure window, and the verifier logs from
   `docs/signature_verification_playbook.md` that prove what was checked.
3. Freeze downstream caches. Push a cache-busting event for any content
   addressable store (CDN, transparency log mirrors) that may serve signed
   payloads signed by the compromised key.

## 3. Forensic timeline

Build a single timeline with five columns. Be ruthless about UTC and
source-of-time.

```
| UTC time | Source | Event | Artifact / hash | Confidence |
|----------|--------|-------|-----------------|------------|
| 2026-01-12T03:14:07Z | vault audit log | token issued | key_id=... | high |
| 2026-01-12T03:22:51Z | CI signer | sig over build#4821 | sha256=... | high |
| 2026-01-12T05:02:10Z | external report | sig presented | sha256=... | medium |
```

Confidence reflects evidence quality: cryptographic proof > log > rumor.

## 4. Revocation

You need two things published, ideally in parallel.

### 4.1 Cryptographic revocation

Issue a signed revocation object that verifiers can fetch offline. Minimal
schema:

```json
{
  "revocation": {
    "issuer": "did:key:z6Mk...",
    "subject_key_id": "<multibase fingerprint of compromised key>",
    "reason": "key_compromise",
    "effective_from": "2026-01-12T03:00:00Z",
    "sequence": 7,
    "next_key": "did:key:z6Mn..."
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "verificationMethod": "did:key:z6Mk...#z6Mk...",
    "created": "2026-01-12T05:30:00Z",
    "proofPurpose": "assertionMethod",
    "proofValue": "<multibase base58btc Ed25519 sig>"
  }
}
```

The revocation MUST be signed by a key that is NOT the compromised one. This
is why every signer needs a pre-published, offline "recovery key" with its
own DID documented in `docs/key_rotation_playbook.md`.

### 4.2 Operational announcement

Push to:
- the project's transparency log / transparency feed,
- a signed status page update,
- any third-party verifiers on the allowlist in
  `docs/trust_anchor_hygiene.md`,
- your own incident channel.

Include the revocation hash so verifiers can cross-check.

## 5. Verification of revocation objects

Run the offline verifier from `docs/offline_signature_verifier.py` against
each revocation you receive. A verifier that does not understand
`Ed25519Signature2020` or cannot reach your revocation feed without network
should be treated as out-of-policy during an incident, not a blocker.

## 6. Rotation

Follow `docs/key_rotation_playbook.md` end to end. The non-negotiable parts
during an incident are:

- New key generated on a clean host, ideally air-gapped, with verifiable
  entropy source.
- Recovery key for the NEW key also generated and stored offline.
- Overlap window: both keys valid for at least one full signature TTL, so
  in-flight artifacts do not suddenly fail.
- Old key never reused. Even for "just one more signature." No.

## 7. Algorithm agility check

Before the new key goes live, confirm the new algorithm+curve combo passes
the checklist in `docs/algorithm_agility_checklist.md`. Post-compromise is
the worst time to discover your verifier cannot parse the new proof type.

## 8. Post-incident

Within 72 hours, file a post-mortem covering at minimum:

- Root cause class: phishing, supply chain, misconfigured secret store,
  insider, cryptographic break.
- Detection latency: time from compromise to detection.
- Containment latency: time from detection to revocation publish.
- Verifier coverage: percentage of verifiers that honored the revocation
  within 1 hour (target >= 95%).
- Action items tied to owners and dates. No "TBD."

## 9. Common pitfalls

- Revocation signed by the compromised key. Useless.
- Revocation published only on a channel the verifier does not watch.
  Worse than useless; it gives false confidence.
- Forgetting to rotate derived material (API tokens, JWKS kids, cached
  public keys in clients). The old public key may keep validating things
  nobody meant to keep valid.
- "We rotated but kept the old key for read-only decryption." That is a
  second compromise waiting to happen; treat it as a fresh key lifecycle.
- Not running the playbook in a drill. First-time execution during an
  incident is how SEV-1s become unrecoverable.

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
