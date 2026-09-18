"""Ed25519 (RFC 8032), in pure Python, because the standard library has no public-key crypto.

This exists to support :mod:`assay_bench.witness`. The problem it solves is gap G2: a submitter
who holds the run secret can compute a valid digest and paste it into an invented string, and a
coherence check cannot tell the difference. The fix is to have a party the submitter does not
control observe the egress and *sign* what it saw -- and a signature is only worth anything if a
third party can check it without holding the signing key. That needs asymmetric crypto, and
`hmac` is symmetric, so the alternative would be "trust whoever holds the shared key", which is
the problem again.

**Read this before relying on it.**

This is a clean, spec-following implementation validated against the RFC 8032 §7.1 test vectors
and against edge cases (non-canonical encodings, small-order points, S out of range). It is
**not** a hardened implementation: it is written for clarity, it uses Python integers, and it
makes no attempt at constant-time behaviour. Python cannot offer constant-time big-integer
arithmetic anyway.

What that means in practice, stated rather than left for someone to discover:

* A **verifier** runs on public data -- a public key, a message and a signature -- so timing
  leaks nothing. Verification is the operation this repository actually needs from a third
  party, and it is safe here.
* **Signing** touches a secret key. Do not sign on a machine where an attacker can measure your
  process, and do not use this module for anything outside this benchmark. If you operate a
  witness in a setting where that matters, sign with `libsodium`/`cryptography` and keep this
  module for verification; the wire format is standard Ed25519, so the two interoperate.

A test asserts this warning stays in the docstring, because a pure-Python crypto module that
loses its caveat is worse than none.
"""

from __future__ import annotations

import hashlib
import os
import secrets

__all__ = ["generate_keypair", "public_key", "sign", "verify", "SIGNATURE_SIZE", "KEY_SIZE",
           "InvalidSignature"]

#: Ed25519 sizes, in bytes. Fixed by the spec; a key or signature of any other length is
#: rejected rather than padded, because silently accepting the wrong size is how a verifier
#: starts approving things it did not check.
KEY_SIZE = 32
SIGNATURE_SIZE = 64

_P = 2 ** 255 - 19
#: Order of the base-point subgroup.
_Q = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)          # sqrt(-1) mod p


class InvalidSignature(Exception):
    """The signature does not verify, or an input was malformed.

    One exception for both on purpose: a caller must not branch differently on "bad encoding"
    and "good encoding, wrong signature", because the two are equally a failure to authenticate
    and distinguishing them in error text is a small oracle.
    """


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


# Points are kept in extended homogeneous coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z and
# T = XY/Z. Affine inversions are the expensive operation; this form needs one per decode
# rather than one per addition.
_BASE_Y = 4 * _inv(5) % _P
_BASE_X = None  # filled in below, after _recover_x exists


def _recover_x(y: int, sign: int) -> int | None:
    """The x coordinate matching `y` on the curve, with the requested sign bit.

    Returns None when no such point exists -- which is a real case for attacker-supplied bytes,
    not a theoretical one, so the caller must handle it rather than assume a point came back.
    """
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        # y = ±1. Only sign 0 is a valid encoding; sign 1 here is the canonical
        # non-canonical encoding that a permissive implementation would wave through.
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if x % 2 != sign:
        x = _P - x
    return x


def _point_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    dd = 2 * z1 * z2 % _P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(scalar: int, point):
    result = (0, 1, 1, 0)                       # neutral element
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, point)
        point = _point_add(point, point)
        scalar >>= 1
    return result


def _point_equal(p, q) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


_BASE_X = _recover_x(_BASE_Y, 0)
_BASE = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % _P)


def _compress(point) -> bytes:
    x, y, z, _ = point
    zinv = _inv(z)
    x, y = x * zinv % _P, y * zinv % _P
    return int.to_bytes(y | ((x & 1) << 255), KEY_SIZE, "little")


def _decompress(data: bytes):
    if len(data) != KEY_SIZE:
        return None
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _sha512(*chunks: bytes) -> bytes:
    digest = hashlib.sha512()
    for chunk in chunks:
        digest.update(chunk)
    return digest.digest()


def _secret_expand(secret_key: bytes) -> tuple[int, bytes]:
    if len(secret_key) != KEY_SIZE:
        raise InvalidSignature(f"a secret key must be {KEY_SIZE} bytes, got {len(secret_key)}")
    h = _sha512(secret_key)
    a = int.from_bytes(h[:32], "little")
    # Clamping, per RFC 8032: clear the low 3 bits so the scalar is a multiple of the cofactor,
    # clear the top bit and set bit 254 so it is in a fixed range.
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(secret_key: bytes) -> bytes:
    """Derive the 32-byte public key from a 32-byte secret key."""
    a, _ = _secret_expand(secret_key)
    return _compress(_point_mul(a, _BASE))


def generate_keypair(secret_key: bytes | None = None) -> tuple[bytes, bytes]:
    """Return `(secret_key, public_key)`, minting the secret from the OS CSPRNG by default."""
    secret_key = secret_key if secret_key is not None else secrets.token_bytes(KEY_SIZE)
    if len(secret_key) != KEY_SIZE:
        raise InvalidSignature(f"a secret key must be {KEY_SIZE} bytes, got {len(secret_key)}")
    return secret_key, public_key(secret_key)


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign `message`. See the module docstring on where signing is and is not appropriate."""
    a, prefix = _secret_expand(secret_key)
    pk = _compress(_point_mul(a, _BASE))
    r = int.from_bytes(_sha512(prefix, message), "little") % _Q
    big_r = _point_mul(r, _BASE)
    rs = _compress(big_r)
    k = int.from_bytes(_sha512(rs, pk, message), "little") % _Q
    s = (r + k * a) % _Q
    return rs + int.to_bytes(s, KEY_SIZE, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """True iff `signature` is a valid Ed25519 signature of `message` under `public`.

    Returns False rather than raising for every failure mode -- wrong length, a public key that
    is not a curve point, a non-canonical R, an S at or above the group order, or simply a wrong
    signature. A caller that wants to know *why* a signature failed is usually a caller about to
    build an oracle out of the answer.
    """
    if len(signature) != SIGNATURE_SIZE or len(public) != KEY_SIZE:
        return False
    a_point = _decompress(public)
    if a_point is None:
        return False
    r_point = _decompress(signature[:32])
    if r_point is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        # Rejecting S >= q is what stops signature malleability: without it, a third party can
        # take a valid signature and produce a different one that also verifies.
        return False
    k = int.from_bytes(_sha512(signature[:32], public, message), "little") % _Q
    left = _point_mul(s, _BASE)
    right = _point_add(r_point, _point_mul(k, a_point))
    return _point_equal(left, right)


def signing_key_from_env(name: str = "ASSAY_WITNESS_KEY") -> bytes | None:
    """Read a hex-encoded signing key from the environment, or return None.

    A witness key belongs in an environment variable or a secret store, never in the repository.
    Returning None rather than raising lets the caller say so in its own words.
    """
    raw = os.environ.get(name)
    if not raw:
        return None
    try:
        key = bytes.fromhex(raw.strip())
    except ValueError:
        raise InvalidSignature(f"${name} is not valid hexadecimal") from None
    if len(key) != KEY_SIZE:
        raise InvalidSignature(f"${name} must be {KEY_SIZE} bytes ({2 * KEY_SIZE} hex chars)")
    return key
