# Sidetree Protocol Trust Audit

**Scope:** A trust-model focused review of the Sidetree protocol (IETF draft-irtf-sidetree) for anchoring DID operations to a target ledger (e.g., Bitcoin/Ethereum/IPFS).

## 1. What Sidetree Claims to Guarantee

Sidetree is *not* a ledger. It is a protocol layer that batches DID create/update/recover/deactivate operations into CAS-stored "anchor files," then periodically commits a single cryptographic summary (e.g., a Merkle root) to an underlying blockchain. Its trust model is therefore a composition of two layers:

1. **Target ledger trust** — inherits the consensus, availability, and censorship-resistance guarantees of the anchor chain.
2. **Sidetree layer trust** — inherits the cryptographic integrity of the CAS + batching + proof generation pipeline.

A verifier MUST evaluate both.

## 2. Trust Anchor Inventory

- **Anchor chain nodes** — full or pruned. Used to verify the on-chain Merkle root matches the most recent batch.
- **CAS (Content Addressable Storage)** — IPFS, distributed CAS, or a single hosted endpoint. Used to fetch operation objects and the anchor file.
- **DID resolution service** — implements the Sidetree spec; assembles a DID Document from operations.
- **Witness network (optional, e.g., ION)** — additional independent observers that gossip and attest to anchor file publication, mitigating a hostile CAS operator who withholds anchor files.

## 3. Concrete Threats

| Threat | Description | Mitigation |
|--------|-------------|------------|
| **Anchor chain reorganization** | A deep reorg rewrites the Merkle root, enabling selective history rewriting. | Wait for deep confirmations (e.g., BTC: 6–60+); check finality gadget output for PoS chains. |
| **CAS withholding** | An attacker controlling the CAS endpoint refuses to serve an anchor file. | Use witnesses; fetch from multiple CAS gateways; verify Merkle root exists on-chain before trusting a DID state. |
| **Operation replay/cross-protocol replay** | The same operation object is replayed against two different Sidetree instances. | Verify the `anchorFileHash` and the `proofOfInclusion` against a Merkle root *you* have observed on-chain — not against a root provided by a third party. |
| **Key compromise (recovery key)** | Attacker controls the DID's recovery key and issues an unauthorized update. | Enforce out-of-band policy: monitor recovery operations, alert on `type: recover`, restrict where the recovery key is held (HSM, multisig). |
| **Algorithm sunset** | A `signingKey` referenced in an operation uses a deprecated/weak algorithm. | Run every resolved key through `examples/verify_detached_sig.py`'s algorithm policy gate; reject Ed25519 variants with known weakness, RSA < 2048, P-256 keys generated with suspect RNGs. |
| **Witness collusion** | A threshold of witnesses colludes to attest a fake anchor. | Choose witnesses from independent operators across jurisdictions; do not co-host witnesses with the CAS or DID resolution service. |
| **Equivocation across resolvers** | Different resolvers return different DID Documents for the same DID. | Pin to your own validation: download the chain tip, walk the protocol, rebuild the document deterministically; reject resolver answers that diverge. |

## 4. Verifier Workflow (Offline Capable)

For each DID being trusted:

1. Fetch the **anchor chain tip** from your own full node (or SPV proof).
2. For the DID, locate the **most recent anchor transaction** referenced by the DID method.
3. Resolve the CAS reference, retrieve the **anchor file** and the relevant **operation batch**.
4. Verify the **Merkle proof**: each operation hashes up to the root committed on-chain.
5. Replay operations in order from `recoveryKey`/`nextRecoveryKey`/`updateCommitment` chain.
6. Resolve the current **signing key** for the DID Document.
7. Apply algorithm policy — see `docs/sig_algo_agility.md`.
8. Cache the **observed root**; subsequent resolutions MUST derive to the same state, otherwise treat as equivocation.

## 5. Why Sidetree Is Not "Trustless"

Sidetree shifts trust from a registry operator to a *composition* of (ledger consensus, witness threshold, CAS replication, your local verifier). The verifier is the load-bearing component. A resolver-only workflow that does not validate against a locally observed anchor chain root is operationally equivalent to trusting a CA — it inherits the resolver's threat model wholesale.

## 6. Auditing Checklist

- [ ] Anchor chain is identified and reachability of a full node is documented.
- [ ] Confirmation depth policy is written down (chain-specific).
- [ ] Witness list is public and operator-diverse.
- [ ] CAS gateway list is independent from the witness set.
- [ ] Algorithm policy on resolved keys is enforced.
- [ ] Equivocation detection (re-derive and compare) is part of the resolution path.
- [ ] Incident response runbook covers recovery-key compromise — see `docs/incident_response_key_compromise.md`.

## 7. Cross-References

- Trust anchors and federation: `docs/trust_anchors.md`, `docs/federated_trust_roots.md`
- Threat model: `docs/threat_model.md`
- Signature verification: `examples/verify_detached_sig.py`, `docs/signature_verification_playbook.md`
- Algorithm agility: `docs/sig_algo_agility.md`
- DID method evaluation: `docs/did_method_evaluation.md`

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
