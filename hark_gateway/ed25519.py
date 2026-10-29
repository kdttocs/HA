"""Ed25519 signatures (RFC 8032), pure Python, stdlib only.

The app only VERIFIES with this (approvals for change commands are signed by Hark with a private key the app never
holds). sign()/public_key() exist so Hark's own helper can use the same code. Not constant-time; fine for verifying
public data, and the signing side runs only on Hark's machine.
"""
import hashlib

p = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, p - 2, p)) % p
I = pow(2, (p - 1) // 4, p)


def _inv(x):
    return pow(x, p - 2, p)


def _recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y * y - 1) * _inv(d * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * I % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_gy = 4 * _inv(5) % p
_gx = _recover_x(_gy, 0)
G = (_gx, _gy, 1, _gx * _gy % p)
O = (0, 1, 1, 0)


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, Gg, H = B - A, D - C, D + C, B + A
    return (E * F % p, Gg * H % p, F * Gg % p, E * H % p)


def _mul(s, P):
    Q = O
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _eq(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def _compress(P):
    zi = _inv(P[2])
    x, y = P[0] * zi % p, P[1] * zi % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % p)


def _h(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")


def _expand(seed):
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed):
    a, _ = _expand(seed)
    return _compress(_mul(a, G))


def sign(seed, msg):
    a, prefix = _expand(seed)
    A = _compress(_mul(a, G))
    r = _h(prefix + msg) % L
    R = _compress(_mul(r, G))
    h = _h(R + A + msg) % L
    s = (r + h * a) % L
    return R + int.to_bytes(s, 32, "little")


def _small_order(P):
    """True for the 8 low-order points (including the identity): 8*P is the identity."""
    return _eq(_mul(8, P), O)


def public_ok(public):
    """True when `public` is a usable Ed25519 public key: a valid point that is not one of the low-order points
    (with such a key, one fixed signature 'verifies' for every message)."""
    try:
        A = _decompress(bytes(public))
        return A is not None and not _small_order(A)
    except Exception:
        return False


def verify(public, msg, signature):
    """True only for a valid signature by `public` (32 bytes) over msg. Refuses non-canonical S (S >= L),
    non-canonical point encodings, and low-order public keys or R values."""
    try:
        if len(public) != 32 or len(signature) != 64:
            return False
        A = _decompress(public)
        if A is None or _small_order(A):
            return False
        R = _decompress(signature[:32])
        if R is None or _small_order(R):
            return False
        s = int.from_bytes(signature[32:], "little")
        if s >= L:
            return False
        h = _h(signature[:32] + public + msg) % L
        return _eq(_mul(s, G), _add(R, _mul(h, A)))
    except Exception:
        return False
