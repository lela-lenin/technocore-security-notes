# JWS / JCS Canonicalization Test Vectors

Purpose: a small, self-contained set of vectors an offline verifier (or a CI test
suite) can use to validate that its JSON Canonicalization Scheme (JCS, RFC 8785)
implementation and its JWS verification path agree on byte-exact payloads.

These vectors are designed for the verifier in `docs/offline_signature_verifier.py`
and are intentionally **minimal** — three cases that together exercise the
trickiest JCS failure modes:

1. Key ordering (JCS requires sorting by Unicode codepoint, recursively).
3. Unicode escape equivalence (`\u00e9` vs the literal `é` byte).
5. Number formatting (no leading zeros, no trailing zero in exponent form).

If your verifier passes all three, it is not "correct in general," but it is
no longer trivially broken — which is the main risk for sidetree-style
CAS protocols where the signature target is the canonical form, not the
user-supplied JSON.

## Vector 1 — key ordering

Input JSON (user form, semantically identical but byte-different):

```json
{"b":2,"a":1,"c":{"y":2,"x":1}}
```

JCS canonical form (expected `payload` bytes before base64url-encoding):

```json
{"a":1,"b":2,"c":{"x":1,"y":2}}
```

If your verifier canonicalizes the user form and gets a different byte string,
it will not produce the same signature as the producer, even though both are
"correct JSON." This is the single most common silent interoperability bug
in sidetree / did:ion style implementations.

## Vector 2 — Unicode escape equivalence

Input JSON (user form A):

```json
{"name":"café"}
```

Input JSON (user form B, same semantic content):

```json
{"name":"caf\u00e9"}
```

JCS canonical form (expected):

```json
{"name":"café"}
```

Both inputs must canonicalize to the **same byte sequence**. A verifier that
hashes the user-supplied bytes directly will accept one form and reject the
other, even though both signatures were produced correctly. JCS resolves this
by requiring all `\uXXXX` escapes to be replaced with their literal UTF-8
encoding during output generation.

## Vector 3 — number formatting

Input JSON (user form A):

```json
{"n":1.0}
```

Input JSON (user form B):

```json
{"n":1e0}
```

Input JSON (user form C):

```json
{"n":1}
```

JCS canonical form (expected):

```json
{"n":1}
```

All three forms canonicalize to exactly the four bytes `{"n":1}`. This is a
frequent source of bugs when verifiers use a JSON parser that "helpfully"
normalizes numbers (e.g., `json.loads` in Python will already parse `1.0`
and `1` to the same float, so if you then re-serialize with default settings
you may get `1.0` back depending on `repr` vs `json.dumps` of a float).
The safe approach is to canonicalize **before** any numeric coercion.

## Reference JCS implementation behavior

The reference behavior these vectors encode (RFC 8785 §3.2.2 and 3.2.3):

- Object keys sorted by **lowest Unicode code point of the escaped form**
  (i.e., `\u00e9` is sorted by `é`, not by the backslash).
- `\uXXXX` escapes (where XXXX ≥ 2 hex digits, ≤ 4, and the character is
  not a control or surrogate) are output as their literal UTF-8 bytes.
- Numbers serialized per ES6 `JSON.stringify` rules, which produce the
  shortest round-trippable representation.

## How to use these with the offline verifier

Drop them into a `tests/` directory and run against
`docs/offline_signature_verifier.py`. Suggested test shape:

```python
# pseudo-code, not part of the verifier itself
import json, hashlib
from offline_signature_verifier import canonicalize

def expect_canonical(input_obj, expected_bytes):
    got = canonicalize(input_obj)
    assert got == expected_bytes, (
        f"JCS mismatch:\n got: {got!r}\n exp: {expected_bytes!r}"
    )

expect_canonical(
    {"b": 2, "a": 1, "c": {"y": 2, "x": 1}},
    b'{"a":1,"b":2,"c":{"x":1,"y":2}}',
)
expect_canonical(
    {"name": "café"},
    b'{"name":"caf\xc3\xa9"}',
)
expect_canonical({"n": 1.0}, b'{"n":1}')
```

(Exact bytes for the `é` test depend on whether the verifier emits the
literal byte or the `\u00e9` escape. RFC 8785 permits the literal byte;
this is the recommended form. Adjust the expected bytes to match the
verifier's documented output policy.)

## Why this file belongs in the repo

The offline verifier can pass a single end-to-end signature check and still
have a JCS bug that causes it to reject valid sidetree operations or accept
forged ones with re-keyed objects. A targeted, human-readable vector set is
cheaper to maintain than a fuzz harness and gives reviewers a concrete thing
to point at during a security review. Pair this with the algorithm-agility
checklist and the trust-anchor-hygiene doc to get a complete small-system
trust posture.

<!-- Authored by Technocore agent DID did:key:z6Mkg7xRUDub7VA83x3FxP8rtmnNS92grS7Aucgasi42K3XX -->
