# Key Compromise Response Playbook

When an Ed25519 signing key used to authenticate messages or artifacts in the
technocore ecosystem is suspected or confirmed to be compromised, the response
must be fast, deterministic, and auditable. This playbook complements
`docs/key_rotation_policies.md` and `docs/trust_anchors.md` by focusing on the
*incident* path rather than the routine rotation path.

## 1. Detection signals

Treat any of the following as a potential compromise trigger:

- A signature verifies against a key that an operator has *not* published.
- Two distinct messages carry the same nonce, sequence number, or logical
  identifier but different signatures.
- A key appears in a `revoked:` header but downstream verifiers still accept it.
- An out-of-band report (operator pager, security contact) flags a private key
  as leaked, lost, or accessible to an adversary.

`verify_signature.py` will surface mismatches between the claimed signer, the
key advertised in the message envelope, and any anchor registered in the local
trust store. Use those mismatches as the first triage input.

## 2. Immediate containment (T+0 to T+15 minutes)

1. **Mark the key as compromised** in the trust store by appending its DID to
   `revoked_keys.json` with an ISO-8601 timestamp and the trigger source:
   ```json
   {
     "did:key:z6Mk...ABC": {
       "revoked_at": "2026-01-15T18:42:00Z",
       "reason": "private_key_leak",
       "source": "operator_pager:trust-auditor"
     }
   }
   ```
2. **Quarantine offline artifacts.** Move any signatures, manifests, or
   receipts produced by the suspect key into a `quarantine/` directory. Do not
   delete them — they are evidence.
3. **Freeze downstream consumers.** If you operate relays, indexers, or caches
   that republished signed data, push a `key-status: revoked` advisory so
   peers can stop trusting the lineage.

## 3. Forensic scoping (T+15 minutes to T+24 hours)

For each artifact signed by the suspect key, answer three questions:

- *When was it signed?* Compare `signed_at` timestamps against the earliest
  credible leak window.
- *What does it assert?* A compromised key can attest to arbitrary content.
  Treat every assertion as untrusted until re-anchored under a successor key.
- *Who relied on it?* Search relay logs, webhook receivers, and human inboxes
  for consumers that may have acted on the artifact.

Use `examples/batch_verify_manifest.py` with a `reject_revoked=True` filter to
generate a list of artifacts that need human re-attestation.

## 4. Recovery and re-anchoring

1. **Generate a successor key** following the policy in
   `docs/key_rotation_policies.md`. Prefer a fresh Ed25519 keypair; do *not*
   reuse material from the compromised key.
2. **Publish a signed rotation statement** that names the compromised DID,
   the successor DID, the revocation timestamp, and a brief rationale. The
   statement itself must be signed by the successor key *and*, if possible,
   countersigned by a higher-tier anchor listed in `docs/trust_anchors.md`.
3. **Update trust anchors.** Operators consuming the trust store should treat
   the rotation statement as authoritative only when:
   - the successor key fingerprint matches the anchor registry, AND
   - the countersignature (if present) chains back to a currently trusted
     anchor, AND
   - the revocation timestamp precedes the earliest post-compromise artifact
     the successor key is now signing.
4. **Re-issue critical artifacts.** Anything whose semantics are time-sensitive
   (revocations, attestations, capability grants) must be re-signed under the
   successor key. Static documents can be left as-is with a tombstone pointer.

## 5. Post-incident hygiene

- Record the full timeline in `incidents/YYYY-MM-DD-<short-id>.md` with hashes
  of the quarantined artifacts.
- Review whether the compromise exploited a gap in
  `docs/threat_model.md` and update the threat model accordingly.
- If the private key left a developer machine, audit endpoint security and
  rotate any shared secrets that lived on the same host.
- Schedule a follow-up review at T+30 days to confirm that no peer still
  trusts the revoked key.

## 6. Communication template

A short, signed advisory is usually enough:

```
Subject: Key revocation — did:key:z6Mk...ABC

The signing key did:key:z6Mk...ABC is revoked effective 2026-01-15T18:42:00Z
due to private_key_leak. All artifacts signed by this key after that moment
must be treated as untrusted. The successor key is did:key:z6Mk...XYZ, with
fingerprint published at https://example.test/anchors/did:key:z6Mk...XYZ.json.

This advisory is signed by the successor key and countersigned by the tier-2
anchor listed in docs/trust_anchors.md.
```

Keep the message terse, machine-parseable, and free of speculation. The goal
is to let other verifiers act without waiting on a human conversation.

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
