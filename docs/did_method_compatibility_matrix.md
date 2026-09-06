# DID Method Compatibility Matrix for Signature Verification

This note maps common DID methods to the concrete verification steps a signer or verifier must perform when a `verificationMethod` references a DID (instead of an inline JWK). It is a companion to `docs/signature_verification_playbook.md` and `docs/offline_signature_verifier.py`.

## Why this matters

Trust-audit failures in federated systems frequently trace back to one of three mistakes:

1. The verifier resolves the DID via the network and accepts whatever `verificationMethod` is returned, even if the controller has been rotated, compromised, or revoked.
2. The verifier caches DID documents without a `proof` or `meta` block and trusts stale entries.
3. The verifier hard-codes a single DID method (e.g. `did:key`) and silently rejects valid signatures from `did:web`, `did:jwk`, or `did:ion`.

A predictable, method-by-method checklist eliminates these classes of bug.

## Canonical resolution pipeline

For every signature referencing a DID:

1. Parse the `kid` (or equivalent) into `(method, method-specific-id, fragment)`.
2. Look up the method in the matrix below.
3. Apply the method-specific resolution rule.
4. Apply the freshness rule (see `docs/trust_anchor_hygiene.md`).
5. Apply the algorithm-agility rule (see `docs/sig_algo_agility.md`).
6. Only then invoke the cryptographic verifier with the resolved public key.

If any step fails or is skipped, the signature MUST be rejected. "Offline" verifiers that cannot perform resolution MUST refuse any DID-based `verificationMethod` and document this as an explicit limitation.

## Matrix

| Method      | Resolvable offline? | Resolution input                | Default verification key type  | Notes for trust audit |
|-------------|---------------------|---------------------------------|--------------------------------|-----------------------|
| `did:key`   | Yes                 | The DID string itself           | Multikey / Multibase           | Pure self-contained public key. Trust is entirely in the identifier. Safe for offline use; verify the multibase prefix matches the declared algorithm. |
| `did:jwk`   | Yes                 | The DID string itself           | JWK                             | Like `did:key` but the key is wrapped in a JWK. Verify the JWK `alg` and `kid` are present and consistent. |
| `did:web`   | No                  | HTTPS GET to `https://<host>/<path>/did.json` | Whatever the DID Doc declares | Network-dependent. Require HTTPS, validate the TLS chain, and confirm `id` matches the requested DID. Beware subdomain takeover; see `docs/trust_anchor_hygiene.md`. |
| `did:ion`   | No (requires Sidetree IPFS/BTC anchoring context) | Anchor URL + operation bundle | `publicKeyJwk` in DID Doc      | See `docs/sidetree_protocol_audit.md`. Verifier must confirm the operation was anchored and not yet pruned. |
| `did:peer`  | Partial             | Out-of-band or peer message     | Multikey / JWK                  | Trust is bootstrapped from the peer channel; record provenance in audit logs. |
| `did:ethr`  | No                  | Ethereum RPC `eth_call`         | `EcdsaSecp256k1RecoveryMethod2020` or `JsonWebKey2020` | Confirm chainId matches the verifier's expected network. A reorg can invalidate recent resolutions. |
| `did:pkh`   | Partial             | Optional CA/BTC resolver        | `EcdsaSecp256k1RecoveryMethod2020` | Public key is recoverable from the address; an optional resolver provides metadata only. |

## Freshness rules

- `did:key` / `did:jwk`: no freshness check needed; the identifier is the key.
- `did:web`: require a `created` / `updated` timestamp not older than the verifier's policy (recommend 24h for high-trust, 7d for low-trust). Reject if missing.
- `did:ion`: require a `proof` chain whose tip is no older than the policy window and whose operations have not been tombstoned.
- `did:ethr`: require a block number not older than the policy finality (recommend 64 blocks for mainnet-equivalent security).

## Algorithm-agility cross-check

For every resolved key, the verifier MUST confirm that:

- The signature suite in the protected header matches the key type.
- The algorithm is on the allow-list for the deployment (see `docs/algorithm_agility_checklist.md`).
- No algorithm downgrade has occurred between the signing time and verification time.

## Worked example

Input signature (header):
```
{
  "alg": "EdDSA",
  "kid": "did:web:example.com#z6Mki...",
  "typ": "JWS"
}
```

Verifier steps:

1. Method: `did:web`, fragment: `z6Mki...`.
2. GET `https://example.com/.well-known/did.json` over a validated TLS channel.
3. Confirm `id` == `did:web:example.com`.
4. Find `verificationMethod` whose `id` ends with `#z6Mki...`.
5. Reject if the `verificationMethod.controller` is not `did:web:example.com` or a documented delegation.
6. Confirm `updated` is within the freshness window.
7. Confirm `EdDSA` is on the allow-list.
8. Decode the multibase public key (`z` prefix => base58btc).
9. Invoke the Ed25519 verifier from `docs/offline_signature_verifier.py`.

Any deviation from the above sequence is grounds for rejection, not silent acceptance.

## Audit checklist

- [ ] Every code path that resolves a DID has a corresponding entry in this matrix.
- [ ] Offline verifiers refuse DID methods marked "No" in the "Resolvable offline?" column.
- [ ] Freshness windows are documented per method and enforced uniformly.
- [ ] Algorithm allow-list is consulted after key resolution, not before.
- [ ] DID document fetches are logged with URL, timestamp, and the hash of the response body.
- [ ] Cached DID documents have an expiry that is strictly shorter than the signature validity window.

## Known gaps

- This matrix does not yet cover `did:btcr`, `did:tz`, `did:stack`, or `did:orb`. Add entries before supporting those methods.
- Long-tail methods may not have a stable `verificationMethod` shape; treat unknown shapes as a hard failure until reviewed.

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
