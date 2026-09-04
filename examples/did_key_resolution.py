"""
did:key resolution and Ed25519 signature verification.

Resolves a did:key identifier (e.g. did:key:z6Mk... for Ed25519) to its raw
public key bytes, then verifies a detached signature over a message file.

A did:key is a self-contained identifier: the public key is encoded directly
in the DID string using a multicodec prefix. No blockchain, no ledger, no
network call. This makes did:key ideal for offline trust bootstrapping.

Spec: https://w3c-ccg.github.io/did-key-spec/
Multicodec table: https://github.com/multiformats/multicodec

Usage:
    python did_key_resolution.py <did:key> <message_file> <signature_file>

Output: JSON {"valid": bool, "did": str, "key_fingerprint_hex": str}
"""

import sys
import json
import hashlib
import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import ed25519
from cryptography.exceptions import InvalidSignature

# Multicodec varint prefixes for key types we care about.
# https://github.com/multiformats/multicodec/blob/master/table.csv
MULTICODEC_ED25519_PUB = b'\xed\x01'   # 0xed = ed25519-pub, length 1 byte
MULTICODEC_ED25519_PRIV = b'\x80\x26'  # not needed for verification, listed for ref


def resolve_did_key(did: str) -> bytes:
    """Extract the raw 32-byte Ed25519 public key from a did:key identifier.

    Format: did:key:<multibase-base58btc><multicodec-bytes>
    Multibase prefix 'z' = base58check (Bitcoin alphabet). The first
    multicodec byte(s) identify the key type; what follows is the key.
    """
    if not did.startswith("did:key:"):
        raise ValueError(f"Not a did:key identifier: {did!r}")

    encoded = did[len("did:key:"):]
    if not encoded or encoded[0] != 'z':
        raise ValueError("did:key payload must use base58btc multibase (prefix 'z')")

    raw = base58.b58decode(encoded[1:])

    if not raw.startswith(MULTICODEC_ED25519_PUB):
        raise ValueError(
            f"Only Ed25519 (multicodec 0xed) is supported by this script; "
            f"got prefix {raw[:2].hex()}"
        )

    pub = raw[len(MULTICODEC_ED25519_PUB):]
    if len(pub) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(pub)}")
    return pub


def verify(did: str, message_path: str, sig_path: str) -> dict:
    pub_bytes = resolve_did_key(did)
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)

    with open(message_path, "rb") as f:
        message = f.read()
    with open(sig_path, "rb") as f:
        signature = f.read()

    if len(signature) != 64:
        return {
            "valid": False,
            "did": did,
            "error": f"signature must be 64 bytes, got {len(signature)}",
        }

    try:
        public_key.verify(signature, message)
        ok = True
    except InvalidSignature:
        ok = False

    # SHA-256 fingerprint of the raw key — handy for cross-checking against
    # out-of-band channels (e.g. "I trust key 3a7f...c091").
    fingerprint = hashlib.sha256(pub_bytes).hexdigest()

    return {
        "valid": ok,
        "did": did,
        "key_fingerprint_hex": fingerprint,
        "message_bytes": len(message),
        "signature_hex": signature.hex(),
    }


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    did, msg, sig = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        result = verify(did, msg, sig)
    except (ValueError, FileNotFoundError, IsADirectoryError) as e:
        print(json.dumps({"valid": False, "error": str(e)}))
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
