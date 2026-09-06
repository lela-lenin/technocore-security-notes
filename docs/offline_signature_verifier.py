#!/usr/bin/env python3
"""
Offline Ed25519 signature verifier for technocore-style DID messages.

This is a standalone reference implementation that complements
docs/signature_verification_playbook.md. It performs:
  1. Parsing a JSON envelope containing `payload` (bytes or UTF-8 string)
     and `signature` (base64url Ed25519 signature).
  2. Decoding the signer DID `did:key:z6Mk...` into a raw 32-byte Ed25519
     public key (multibase-decoded from the `z6Mk` multicodec prefix
     0xed01).
  3. Verifying the signature with PyNaCl (libsodium) in a single step.

Offline guarantees:
  - No network calls.
  - No filesystem access beyond reading the input path.
  - Deterministic output (constant-time compare via libsodium).

Usage:
  python3 offline_signature_verifier.py envelope.json
  echo '{"payload":"hello","signature":"...","did":"did:key:z6Mk..."}' \
      | python3 offline_signature_verifier.py -

Envelope schema:
  {
    "payload":   "<utf-8 string or base64url bytes>",
    "payload_encoding": "utf-8" | "base64url",   // optional, default utf-8
    "signature": "<base64url Ed25519 signature, 64 bytes decoded>",
    "did":       "did:key:z6Mk..."
  }

Exit codes:
  0  signature valid
  1  signature invalid
  2  usage / parse error
  3  missing dependency (PyNaCl)
"""

from __future__ import annotations

import base64
import json
import sys
from typing import Tuple

# ---- Base64url helpers --------------------------------------------------------

_B64URL_PAD = "=" * 4  # used only if a length-misaligned input slips in

def b64url_decode(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += _B64URL_PAD[: (4 - len(s) % 4) % 4]
    return base64.b64decode(s)

def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

# ---- DID:key decoding --------------------------------------------------------
# did:key for Ed25519 uses multicodec prefix 0xed 0x01, then 32-byte raw pubkey,
# all wrapped in base58btc with multibase prefix 'z'.
# Reference: https://w3c-ccg.github.io/did-method-key/

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58_decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    out = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    # Restore leading '1' zeros (each = 0x00 byte).
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + out

def did_key_to_raw_ed25519(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise ValueError("unsupported DID method or multibase prefix")
    body = did[len("did:key:"):]
    if not body or body[0] != "z":
        raise ValueError("expected multibase 'z' (base58btc)")
    raw = b58_decode(body[1:])
    if len(raw) < 34 or raw[0] != 0xED or raw[1] != 0x01:
        raise ValueError("not an Ed25519 did:key (bad multicodec prefix)")
    pubkey = raw[2:]
    if len(pubkey) != 32:
        raise ValueError(f"unexpected Ed25519 pubkey length {len(pubkey)}")
    return pubkey

# ---- Payload normalization ----------------------------------------------------

def normalize_payload(env: dict) -> bytes:
    enc = env.get("payload_encoding", "utf-8").lower()
    val = env["payload"]
    if enc == "utf-8":
        if isinstance(val, str):
            return val.encode("utf-8")
        raise ValueError("payload_encoding=utf-8 requires string payload")
    if enc == "base64url":
        if isinstance(val, str):
            return b64url_decode(val)
        raise ValueError("payload_encoding=base64url requires string payload")
    raise ValueError(f"unknown payload_encoding: {enc}")

# ---- Verification ------------------------------------------------------------

def verify(did: str, payload: bytes, signature_b64: str) -> Tuple[bool, str]:
    try:
        from nacl.signing import VerifyKey  # PyNaCl
    except ImportError:
        return (False, "PyNaCl not installed; pip install pynacl")
    try:
        pubkey = did_key_to_raw_ed25519(did)
        sig = b64url_decode(signature_b64)
    except Exception as e:
        return (False, f"decode error: {e}")
    if len(sig) != 64:
        return (False, f"signature length {len(sig)} != 64")
    try:
        VerifyKey(pubkey).verify(payload, sig)
        return (True, "signature valid")
    except Exception as e:
        # nacl.exceptions.BadSignatureError is the expected failure mode.
        return (False, f"signature invalid: {type(e).__name__}")

# ---- I/O ----------------------------------------------------------------------

def load_envelope(source: str) -> dict:
    if source == "-":
        data = sys.stdin.read()
    else:
        with open(source, "r", encoding="utf-8") as f:
            data = f.read()
    try:
        env = json.loads(data)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON: {e}") from e
    for required in ("payload", "signature", "did"):
        if required not in env:
            raise ValueError(f"missing field: {required}")
    return env

def main(argv: list) -> int:
    if len(argv) != 2:
        print("usage: offline_signature_verifier.py envelope.json | -", file=sys.stderr)
        return 2
    try:
        env = load_envelope(argv[1])
        payload = normalize_payload(env)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    ok, msg = verify(env["did"], payload, env["signature"])
    print(msg)
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv))

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
