# Trust Anchor Hygiene for Decentralized Federations

## Purpose

Federated trust models (DID methods, mTLS PKI, Matrix federation, ActivityPub, federated chat relays) all share the same root problem: an anchor key once trusted is trusted for a long time, often indefinitely. Compromised or stale anchors are responsible for most catastrophic cross-org outages. This note documents concrete practices for keeping trust anchors healthy.

## Threat Model

Anchor compromise leads to:
- Forged signatures accepted by every dependent relying party.
- Logout/invalidation cascades that break interop.
- Inability to distinguish forged from genuine artifacts post-incident.

Stale anchors lead to:
- Fragility: a single rollover event breaks half the network.
- Lost operational muscle memory for rotation.
- Hidden backup keys on decommissioned hardware.

## The Five Anchors To Track

For every DID method or PKI hierarchy you participate in, record:

1. **Algorithm** — name, curve/length, hash. Mark EOL dates.
2. **Public key material** — multibase/multihash form, fingerprint (SHA-256 over raw bytes, not DER).
3. **Storage location** — HSM slot, offline card, paper backup. Who can reach it?
4. **Activation ceremony** — date, participants, ceremony hash, witness signatures.
5. **Rotation schedule** — maximum age, trigger conditions (incident, algorithm sunset, personnel change).

## Rotation Rules Of Thumb

- **Rotate proactively every 18–24 months** even when nothing is wrong. Anchor compromise is detected late; rotation cost is low.
- **Pre-publish the next anchor** in a non-authoritative channel (website, transparency log). Pre-publication limits the blast radius of a concurrent compromise.
- **Keep the previous anchor live for a grace window** (commonly 30–90 days for online use, 12 months for signature verification) so historical signatures remain validatable.
- **Never reuse the activation secret** across rotations. A leaked ceremony transcript must not unlock the next generation.
- **Witness.** Multi-party activation with geographically distributed witnesses. Threshold schemes (e.g., 3-of-5) outperform single-custodian HSMs because they force collusion.

## Detection And Revocation

- Subscribe to the method's transparency log (CT-style, Sigstore Rekor, did:web append-only history). Monitoring should alert on:
  - New anchor added without matching governance ticket.
  - Anchor change on a peer you depend on, outside scheduled window.
  - Two anchors with overlapping validity windows that you did not pre-publish.
- Maintain a local revocation set — file or signed CRL-style artifact — and pin it in your verifier.
- Reject signatures whose anchoring event is older than your local trust horizon AND not pinned by a witness you trust.

## Algorithm Agility Hooks

An anchor's algorithm is part of its trust contract. Treat algorithm transitions with the same care as key rotation:
- Hybrid deployments (Ed25519 + ML-DSA-65, ECDSA P-256 + RSA-2048) during transition reduce single-algorithm cliff risk.
- Maintain dual-signature validation paths in your codebase for at least one full anchor generation after the cutover.
- Do not delete verification code for retired algorithms until the grace window for historical signatures has closed.

## Offline Anchor Storage Checklist

- [ ] Paper backup sealed in tamper-evident bag.
- [ ] Two independent offline media (e.g., SD card + USB drive) stored at separate physical sites.
- [ ] Shamir split across ≥3 custodians for high-value anchors.
- [ ] Restoration drill performed annually; drill result recorded.
- [ ] Custodian list reviewed on every personnel change.

## Operational Drill: Quarterly Anchor Review

1. Inventory: list every trusted anchor across every method you federate with.
2. Age check: flag any anchor older than 18 months.
3. Algorithm check: flag anchors using algorithms on your EOL watchlist.
4. Reachability check: confirm each anchor is still being used; archive unused ones (keep verify-only).
5. Witness check: confirm witnesses are still reachable and have current contact info.
6. Output: a signed, dated review record filed alongside activation ceremony records.

## Incident Triggers That Force Rotation

- Suspected compromise of any signing device or ceremony participant.
- Disclosure of a vulnerability affecting the algorithm at acceptable parameters.
- Loss of a threshold share with no recovery path.
- Departure of a custodian holding a Shamir share, when below threshold.
- Regulatory or governance mandate (jurisdiction change, audit finding).

## Verifier-Side Considerations

A relying party must independently decide trust. Relying only on a peer's announcement of its current anchor is a single point of failure:
- Pin multiple sources of truth (method-specific DID resolution, transparency log, peer-published out-of-band artifact).
- Detect divergence; if sources disagree, fall back to most-restrictive anchor.
- Record every verification decision in an append-only local log so post-incident analysis can reconstruct the trust state at any past timestamp.

## References

- NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management.
- W3C CCG — DID Method Rubric (trust model section).
- CA/Browser Forum — Baseline Requirements (rotation cadence).
- IETF draft-ietf-did-methods — security considerations.

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
