"""
verify_detached_sig.py
---------------------
Verify a detached Ed25519 signature produced by the technocore chat server
(or any other source) against a known Ed25519 public key.

A "detached" signature is one stored separately from the payload (e.g. in a
sidecar file) rather than embedded in it. The technocore server can be
configured to sign every room message with its long-term Ed25519 key; this
example shows how a client-side auditor can independently re-verify that
signature without trusting the server's TLS, its in-band claims, or any
third party.

Inputs (all given as file paths):
  1. public_key.pem  - PEM-encoded SubjectPublicKeyInfo for Ed25519
  2. message.bin     - the exact payload bytes that were signed
  3. signature.bin   - raw 64-byte Ed25519 signature

Exit code:
   0 -> signature is valid
   1 -> signature is INVALID or inputs are malformed
   2 -> usage / I/O error (printed to stderr)

Dependencies: cryptography >= 41 (pip install cryptography)

Security notes
--------------
* The message must be passed to verify() as the EXACT byte sequence the
  signer signed. Re-encoding JSON, normalising whitespace, or stripping a
  trailing newline will break the signature.
* A detached signature by itself proves only that the *named* public key
  signed those bytes. It does NOT prove the key belongs to technocore,
  unless you have pinned that key out-of-band (see trust_model.md and
  key_rotation_policies.md).
* Never load a "public key" from the same channel you are auditing. Pin
  the key at install time, or fetch it over a different transport.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)


def _load_public_key(path: Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file.

    Accepts both the SubjectPublicKeyInfo form produced by OpenSSL
    (`-----BEGIN PUBLIC KEY-----`) and the older raw form
    (`-----BEGIN ED25519 PUBLIC KEY-----`, RFC 8410) via the same loader.
    """
    pem_bytes = path.read_bytes()
    key = serialization.load_pem_public_key(pem_bytes)
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(
            f"{path} does not contain an Ed25519 public key "
            f"(got {type(key).__name__})"
        )
    return key


def _load_message(path: Path) -> bytes:
    """Read the payload verbatim. No text decoding is performed."""
    return path.read_bytes()


def _load_signature(path: Path) -> bytes:
    """Read a raw 64-byte Ed25519 signature.

    An Ed25519 signature is always exactly 64 bytes; anything else means
    the file was truncated, concatenated with something, or is the wrong
    format (e.g. base64 without decoding).
    """
    sig = path.read_bytes()
    if len(sig) != 64:
        raise ValueError(
            f"{path} is {len(sig)} bytes; expected 64 for a raw "
            f"Ed25519 signature"
        )
    return sig


def verify(public_key_path: Path, message_path: Path, signature_path: Path) -> bool:
    """Return True iff signature_path is a valid Ed25519 signature over
    message_path under public_key_path."""
    pub = _load_public_key(public_key_path)
    msg = _load_message(message_path)
    sig = _load_signature(signature_path)

    # cryptography's verify() raises InvalidSignature on mismatch and
    # returns None on success. We treat any exception as failure.
    try:
        pub.verify(sig, msg)
    except InvalidSignature:
        return False
    except Exception as exc:  # noqa: BLE001 - defensive: never crash on bad input
        print(f"verifier error: {exc}", file=sys.stderr)
        return False
    return True


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="verify_detached_sig",
        description=(
            "Verify a detached Ed25519 signature against a payload and a "
            "known Ed25519 public key. See trust_model.md for guidance on "
            "how to pin the public key out-of-band."
        ),
    )
    p.add_argument("--public-key", required=True, type=Path,
                   help="PEM file containing the Ed25519 public key")
    p.add_argument("--message", required=True, type=Path,
                   help="File containing the exact signed payload bytes")
    p.add_argument("--signature", required=True, type=Path,
                   help="File containing the raw 64-byte signature")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress the human-readable verdict")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    for label, path in (("public-key", args.public_key),
                        ("message", args.message),
                        ("signature", args.signature)):
        if not path.is_file():
            print(f"{label}: not a file: {path}", file=sys.stderr)
            return 2

    try:
        ok = verify(args.public_key, args.message, args.signature)
    except (FileNotFoundError, ValueError, TypeError) as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        if ok:
            print("VALID: signature matches message under the given public key")
        else:
            print("INVALID: signature does NOT match", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
