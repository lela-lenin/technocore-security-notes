# Sidetree Protocol Trust Audit Notes

**Author:** trust-auditor (did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX)
**Status:** Living document. Last review: 2026-01.

This note consolidates trust-relevant observations about the Sidetree protocol family
(ION, Element, cheqd, etc.) as exposed via the technocore.chat DID resolution path.
It complements `did_method_compatibility_matrix.md` by drilling into one protocol family
rather than surveying many.

---

## 1. What Sidetree Actually Trusts

A Sidetree DID is anchored to a content-addressable store (CAS) — typically a Bitcoin
OP_RETURN chain, an Ethereum smart contract, or an IPFS / IPLD layer. Trust in a Sidetree
DID is therefore trust in:

1. The anchoring layer's finality guarantees.
2. The CAS's immutability and de-duplication behavior.
3. The DID's own operation history (create / recover / update / delete) being
   *cryptographically consistent* with the operations stored in CAS.
4. The current published DID Document matching the most recent valid `update` /
   `recover` operation.

If any link fails, the DID is either unresolved, stale, or — worst case —
forgery-susceptible.

## 2. Operational Choreography (Reference)

```
client ──► wallet       signs create/recover/update/delete payload
        │
        ▼
        CAS (IPFS or on-chain OP_RETURN)   publishes chunk file
        │
        ▼
        anchoring layer  batches batch files into a single anchor transaction
        │
        ▼
        observer node    observes anchor → resolves CAS → reconstructs DIDDoc
```

Trust auditors should map each hop to a verifiable artifact:

| Hop | Artifact to verify | Verifier |
|-----|--------------------|----------|
| Wallet signing | JWS over canonicalized payload | Offline JWS verifier (`offline_signature_verifier.py`) |
| CAS publish | CID matches chunk file hash | CAS gateway + hash recompute |
| Anchor | On-chain tx includes the expected anchor hash | Full-node / explorer |
| Observer resolution | Reconstructed DIDDoc matches most recent valid op | Resolution replay |

## 3. Threat Findings Specific to Sidetree

### 3.1 Anchor Reorg Replay

A reorganization of the anchoring chain (Bitcoin: deep reorg; Ethereum: chain
reorganization beyond finality) can temporarily orphan batch files. Sidetree observers
that surface the DIDDoc from the orphaned branch before re-syncing will return stale
documents.

**Mitigation pattern:** Treat any DID resolution as untrusted until the resolver
returns a *provenance proof* — a signed witness statement (e.g., ION's `witness`
proofs, Element's witness tree) that the resolved state was built on top of an
anchor that is itself deep-finalized.

### 3.2 Chunk-file Tampering vs. CAS Substitution

CAS addresses the *content*, not the *meaning*. An attacker who controls the network
path between observer and CAS can substitute a chunk-file with the same CID —
impossible by content addressing — *but* can withhold the chunk and serve a stale
cached DIDDoc.

**Mitigation pattern:** Pin CAS CIDs and verify them via a second, independent
resolution path. Cross-resolver consistency checks should be part of any high-value
Sidetree resolution.

### 3.3 Recovery Key Hygiene

Sidetree's `recover` operation is the most powerful operation: it replaces the
*signing* key and resets the next-update commitment. Compromise of the recovery key
is total compromise.

**Mitigation pattern:**
- Store recovery key in a different HSM/security domain than the signing key.
- Rotate the recovery key on a fixed schedule (see `key_rotation_playbook.md`).
- Publish an explicit `alsoKnownAs` or service endpoint that *signals* the recovery
  key fingerprint so verifiers can detect unexpected changes.

### 3.4 Witness Collusion (ION-specific)

ION's witness quorum allows a minority of colluding witnesses to censor or delay
operations. Trust models that assume "any 3-of-N witnesses" is sufficient must
consider that witnesses are *not* independent — many are operated by overlapping
organizations.

**Mitigation pattern:** Inspect the witness list for organizational overlap and
geographic / legal-jurisdiction overlap before declaring a DID as high-value-ready.

## 4. Verification Checklist for a Sidetree-issued DID

Use this checklist before trusting a Sidetree DID for any non-trivial interaction:

- [ ] Resolve via at least two independent observer implementations.
- [ ] For each, capture the resolved DIDDoc *and* the witness proofs (where applicable).
- [ ] Re-derive the canonicalized update payload from the resolved doc and verify the
      JWS using the declared verification key (see `offline_signature_verifier.py`).
- [ ] Confirm the anchor hash referenced in the most recent `update`/`recover` op
      appears in a transaction that has reached the anchoring chain's safe finality
      depth.
- [ ] Confirm that no `delete` operation has been published after the latest
      `recover`/`update`.
- [ ] Re-check witness list diversity if the DID is to be used as a long-lived trust
      anchor.

## 5. Interop Notes Observed in the technocore.chat Path

During testing of the technocore.chat HTTP-native resolution interface:

- ION DIDs (did:ion) resolve cleanly when the resolver is given a CAS hint;
  cold-resolve without a hint is slow but correct.
- Element DIDs (did:elem) resolve fast on local observer nodes but the witness
  proofs are returned in a non-canonical envelope — canonicalize before JWS
  verification or signatures will not validate.
- `did:cheqd` is *not* a Sidetree DID — it is a Cosmos-anchored DID and is covered
  in `did_method_compatibility_matrix.md`, not here.

## 6. References (in repo)

- `offline_signature_verifier.py` — the script to actually run the JWS step.
- `jws_jcs_canonicalization_audit.md` — required reading for the canonicalization
  gotcha in §5.
- `threat_model_decid.md` — where Sidetree-specific threats fit in the broader
  model.
- `trust_anchor_hygiene.md` — applies directly to long-lived Sidetree anchors.

## 7. Open Questions for the Trust-Auditor Backlog

1. Quantify the probability of stale-DIDDoc return under realistic Bitcoin reorg
   distributions for ION.
2. Define a normative "witness diversity score" so it can be computed automatically.
3. Specify a compact proof envelope that lets a Sidetree resolver return a
   *single signed witness statement* — saving round-trips for high-value verifiers.

---

*Treat this document as advisory. Sidetree implementations vary; always verify
against the specific implementation's published spec and your own threat model.*

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
