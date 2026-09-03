#!/usr/bin/env python3
"""
batch_verify_manifest.py - Verify a signed manifest of multiple artifacts.

Reads a JSON manifest describing several artifacts and the Ed25519 signature
produced over the canonical concatenation of their content. This is a common
pattern in supply-chain / release verification: instead of signing each artifact
-- separately, the publisher signs a manifest that binds filenames to hashes and
-- then signs that manifest with a long-lived signing key.

Manifest schema (UTF-8 JSON):
{
    "manifest_version": 1,
    "created": "2026-01-15T12:00:00Z",
    "subject_did": "did:key:z6Mk...",
    "artifacts": [
        {"path": "bin/tool-linux",   "sha256": "<hex>"},
        {"path": "bin/tool-macos",   "sha256": "<hex>"},
        {"path": "docs/release.md",  "sha256": "<hex>"}
    ],
    "canonicalization": "utf-8-json-sort-keys-no-whitespace",
    "signature": {
        "algorithm": "ed25519",
        "public_key": "<32-byte hex>",
        "value":      "<64-byte hex>"
    }
}

The bytes that are signed are the canonical artifact body:
    path\\n + sha256_hex\\n   for each artifact, in declared order.

Usage:
    python batch_verify_manifest.py manifest.json --root ./dist
    python batch_verify_manifest.py manifest.json --root ./dist --public-key <hex>

Exit codes:
    0  - manifest signature OK and every artifact hash matches
    1  - signature invalid / wrong key
    2  - hash mismatch (tampered or missing artifact)
    3  - malformed manifest / IO error
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

EXPECTED_ALG = "ed25519"
SUPPORTED_VERSION = 1


def canonical_body(artifacts: list[dict]) -> bytes:
    """Build the deterministic byte string that was signed.

    Order is taken from the manifest; we never sort, because doing so would
    -- let an attacker rearrange entries without invalidating the signature.
    """
    out = bytearray()
    for art in artifacts:
        path = art["path"]
        digest = art["sha256"].lower()
        out += path.encode("utf-8") + b"\n"
        out += digest.encode("ascii") + b"\n"
    return bytes(out)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_manifest(manifest_path: Path, root: Path, pinned_key_hex: str | None) -> int:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read manifest: {exc}", file=sys.stderr)
        return 3

    if manifest.get("manifest_version") != SUPPORTED_VERSION:
        print(f"error: unsupported manifest_version {manifest.get('manifest_version')!r}", file=sys.stderr)
        return 3

    sig_block = manifest.get("signature")
    if not isinstance(sig_block, dict):
        print("error: manifest missing signature block", file=sys.stderr)
        return 3
    if sig_block.get("algorithm") != EXPECTED_ALG:
        print(f"error: unsupported algorithm {sig_block.get('algorithm')!r}", file=sys.stderr)
        return 3

    try:
        pub_hex = sig_block["public_key"]
        sig_hex = sig_block["value"]
        pub_bytes = bytes.fromhex(pub_hex)
        sig_bytes = bytes.fromhex(sig_hex)
        if len(pub_bytes) != 32 or len(sig_bytes) != 64:
            raise ValueError("unexpected key/signature length")
    except (KeyError, ValueError) as exc:
        print(f"error: malformed signature block: {exc}", file=sys.stderr)
        return 3

    if pinned_key_hex and pinned_key_hex.lower() != pub_hex.lower():
        print("error: public key does not match --pin value", file=sys.stderr)
        return 1

    body = canonical_body(manifest["artifacts"])
    try:
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, body)
    except InvalidSignature:
        print("FAIL: manifest signature is invalid", file=sys.stderr)
        return 1

    bad = []
    for art in manifest["artifacts"]:
        rel = Path(art["path"])
        if rel.is_absolute() or ".." in rel.parts:
            print(f"error: unsafe path in manifest: {art['path']!r}", file=sys.stderr)
            return 3
        target = (root / rel).resolve()
        if root.resolve() not in target.parents and target != root.resolve():
            print(f"error: path escapes root: {art['path']!r}", file=sys.stderr)
            return 3
        if not target.is_file():
            bad.append((art["path"], "missing"))
            continue
        digest = sha256_file(target)
        if digest.lower() != art["sha256"].lower():
            bad.append((art["path"], f"hash mismatch (got {digest})"))

    if bad:
        print("FAIL: artifact integrity check failed:")
        for path, reason in bad:
            print(f"  - {path}: {reason}")
        return 2

    subject = manifest.get("subject_did", "<unknown subject>")
    print(f"OK: manifest signature valid, {len(manifest['artifacts'])} artifacts verified")
    print(f"    signed by: {subject}")
    print(f"    key:    {pub_hex}")
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Verify a signed artifact manifest.")
    ap.add_argument("manifest", type=Path, help="Path to the signed manifest JSON.")
    ap.add_argument("--root", type=Path, required=True,
                    help="Directory the manifest's paths are relative to.")
    ap.add_argument("--public-key", default=None,
                    help="Optional 32-byte hex public key to pin against.")
    args = ap.parse_args(argv)
    return verify_manifest(args.manifest, args.root, args.public_key)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
