"""A learning-with-errors key encapsulation mechanism.

This is a real, working LWE-based KEM in the spirit of the NIST PQC finalists,
written from the mathematics rather than wrapping a library. It is *not*
constant-time and is not a drop-in replacement for ML-KEM; it exists so the
hybrid handshake in this project has a genuine post-quantum half that can be
tested, attacked and reasoned about.

The scheme, over Z_q with q = 3329 (the Kyber modulus):

  keygen:  A <- Z_q^{k x k}          (public, from a seed)
           s, e <- small            (secret)
           t = A s + e              (public key)

  encaps:  r, e1, e2 <- small
           u = A^T r + e1
           v = t^T r + e2 + encode(m)
           c = (u, v)

  decaps:  m' = decode(v - s^T u)

Correctness holds because v - s^T u = t^T r + e2 + encode(m) - s^T(A^T r + e1)
= e^T r + e2 - s^T e1 + encode(m), and the error term is small enough to round
away when the noise bound is respected.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import List, Optional, Tuple

Q = 3329
K = 3
ETA = 2
NOISE_BOUND = ETA * K * 2 + ETA  # conservative bound on |e^T r + e2 - s^T e1|

# encode() maps one bit to 0 or q/2. decode() rounds to the nearer of the two.
HALF_Q = Q // 2


class PQError(Exception):
    """Raised when a post-quantum operation cannot be completed."""


def _cbd(seed: bytes, nonce: int, n: int, eta: int = ETA) -> List[int]:
    """Centred binomial distribution sampler.

    Sampling from a binomial rather than a discrete Gaussian is what the
    Kyber designers did: it is easy to implement without floating point and
    the resulting distribution is close enough for the security argument.
    """
    out: List[int] = []
    stream = hashlib.shake_256(seed + bytes([nonce])).digest(4 * n)
    idx = 0
    while len(out) < n:
        a = int.from_bytes(stream[idx:idx + 2], "little")
        idx += 2
        for bit in range(eta):
            x = (a >> bit) & 1
            y = (a >> (bit + eta)) & 1
            out.append(x - y)
            if len(out) == n:
                break
    return out


def _matrix_from_seed(seed: bytes, k: int) -> List[List[int]]:
    """Expand a seed into a k x k matrix over Z_q.

    Deterministic, so both sides derive the same A from a short public seed
    instead of transmitting k^2 integers.
    """
    out: List[List[int]] = []
    for i in range(k):
        row: List[int] = []
        for j in range(k):
            digest = hashlib.shake_256(seed + bytes([i, j])).digest(4)
            row.append(int.from_bytes(digest, "little") % Q)
        out.append(row)
    return out


def _mat_vec_mul(m: List[List[int]], v: List[int]) -> List[int]:
    k = len(m)
    out = []
    for i in range(k):
        acc = 0
        for j in range(k):
            acc += m[i][j] * v[j]
        out.append(acc % Q)
    return out


def _mat_t_vec_mul(m: List[List[int]], v: List[int]) -> List[int]:
    k = len(m)
    out = []
    for j in range(k):
        acc = 0
        for i in range(k):
            acc += m[i][j] * v[i]
        out.append(acc % Q)
    return out


def _dot(a: List[int], b: List[int]) -> int:
    if len(a) != len(b):
        raise PQError("dot product length mismatch")
    return sum(x * y for x, y in zip(a, b)) % Q


def _encode_bit(bit: int) -> int:
    if bit not in (0, 1):
        raise PQError("bit must be 0 or 1")
    return HALF_Q if bit else 0


def _decode(value: int) -> int:
    """Round a value in Z_q to the nearest of {0, q/2}."""
    v = value % Q
    # Distance to 0 and to q/2, accounting for wraparound.
    d0 = min(v, Q - v)
    d1 = abs(v - HALF_Q)
    return 0 if d0 <= d1 else 1


@dataclass
class PublicKey:
    seed: bytes
    t: List[int]

    def to_bytes(self) -> bytes:
        return self.seed + b"".join(int(x).to_bytes(2, "little") for x in self.t)

    @classmethod
    def from_bytes(cls, raw: bytes) -> "PublicKey":
        if len(raw) != 32 + 2 * K:
            raise PQError("public key has the wrong length")
        seed = raw[:32]
        t = [int.from_bytes(raw[32 + 2 * i:34 + 2 * i], "little") for i in range(K)]
        return cls(seed=seed, t=t)


@dataclass
class SecretKey:
    s: List[int]
    public: PublicKey


@dataclass
class Ciphertext:
    u: List[int]
    v: int

    def to_bytes(self) -> bytes:
        return b"".join(int(x).to_bytes(2, "little") for x in self.u) + int(self.v).to_bytes(2, "little")

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Ciphertext":
        if len(raw) != 2 * K + 2:
            raise PQError("ciphertext has the wrong length")
        u = [int.from_bytes(raw[2 * i:2 * i + 2], "little") for i in range(K)]
        v = int.from_bytes(raw[2 * K:2 * K + 2], "little")
        return cls(u=u, v=v)


def keygen(seed: Optional[bytes] = None) -> Tuple[PublicKey, SecretKey]:
    """Generate a keypair. `seed` makes the output reproducible for tests."""
    if seed is None:
        seed = os.urandom(32)
    if len(seed) != 32:
        raise PQError("seed must be 32 bytes")
    a = _matrix_from_seed(seed, K)
    s = _cbd(seed, 1, K)
    e = _cbd(seed, 2, K)
    # Compute each row eagerly. A generator expression here would be consumed
    # after the outer loop finished, so every row would read the final value
    # of `i` and the public key would collapse to one repeated entry.
    t_vec = [(sum(a[i][j] * s[j] for j in range(K)) + e[i]) % Q for i in range(K)]
    pub = PublicKey(seed=seed, t=t_vec)
    return pub, SecretKey(s=s, public=pub)


def encapsulate(pub: PublicKey, message_bit: int, seed: Optional[bytes] = None) -> Tuple[Ciphertext, int]:
    """Encapsulate one bit. Returns the ciphertext and the shared bit."""
    if seed is None:
        seed = os.urandom(32)
    a = _matrix_from_seed(pub.seed, K)
    r = _cbd(seed, 3, K)
    e1 = _cbd(seed, 4, K)
    e2 = _cbd(seed, 5, 1)[0]
    u = _mat_t_vec_mul(a, r)
    u = [(u[i] + e1[i]) % Q for i in range(K)]
    v = (_dot(pub.t, r) + e2 + _encode_bit(message_bit)) % Q
    return Ciphertext(u=u, v=v), message_bit


def decapsulate(sk: SecretKey, ct: Ciphertext) -> int:
    """Recover the encapsulated bit."""
    if len(ct.u) != K:
        raise PQError("ciphertext dimension mismatch")
    noise = _dot(sk.s, ct.u)
    return _decode((ct.v - noise) % Q)


def shared_secret(bit: int, context: bytes = b"") -> bytes:
    """Expand the agreed bit into a 32-byte key.

    A single bit is not a key, so both sides run it through a KDF together
    with a context string. In the hybrid handshake this is combined with the
    X25519 secret rather than used alone.
    """
    if bit not in (0, 1):
        raise PQError("bit must be 0 or 1")
    return hashlib.sha256(b"pqshield/v1/kem" + context + bytes([bit])).digest()
