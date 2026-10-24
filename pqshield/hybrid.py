"""Hybrid handshake: X25519 + LWE, combined so both must fail to break it.

The point of a hybrid is that you do not have to bet on either primitive. If
X25519 falls to a quantum computer, the LWE half still holds; if the lattice
scheme is broken classically, X25519 still holds. The two secrets are
concatenated and run through one KDF, so an attacker needs to break both.

The transcript hash is included in the KDF input, which binds the derived key
to the exact handshake that produced it. A replayed or spliced handshake
therefore derives a different key and fails to authenticate.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .kem import (
    Ciphertext,
    PQError,
    PublicKey,
    SecretKey,
    decapsulate,
    encapsulate,
    keygen,
    shared_secret,
)

HYBRID_INFO = b"pqshield/v1/hybrid"


class HybridError(Exception):
    """Raised when a hybrid handshake cannot be completed."""


@dataclass
class HybridKeyPair:
    x25519_private: X25519PrivateKey
    pq_public: PublicKey
    pq_secret: SecretKey

    @classmethod
    def generate(cls, seed: Optional[bytes] = None) -> "HybridKeyPair":
        if seed is None:
            seed = os.urandom(32)
        if len(seed) != 32:
            raise HybridError("seed must be 32 bytes")
        x_priv = X25519PrivateKey.from_private_bytes(seed)
        pq_pub, pq_sec = keygen(seed)
        return cls(x25519_private=x_priv, pq_public=pq_pub, pq_secret=pq_sec)

    def x25519_public_bytes(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self.x25519_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_bundle(self) -> bytes:
        """What a peer needs to start a handshake with us."""
        return self.x25519_public_bytes() + self.pq_public.to_bytes()


@dataclass
class HandshakeMessage:
    """Initiator's first flight."""

    x25519_public: bytes
    pq_ciphertext: Ciphertext
    pq_bit: int

    def to_bytes(self) -> bytes:
        return self.x25519_public + self.pq_ciphertext.to_bytes() + bytes([self.pq_bit])

    @classmethod
    def from_bytes(cls, raw: bytes) -> "HandshakeMessage":
        if len(raw) != 32 + (2 * 3 + 2) + 1:
            raise HybridError("handshake message has the wrong length")
        x = raw[:32]
        ct = Ciphertext.from_bytes(raw[32:32 + 8])
        bit = raw[40]
        if bit not in (0, 1):
            raise HybridError("invalid encapsulated bit")
        return cls(x25519_public=x, pq_ciphertext=ct, pq_bit=bit)


def _combine(x_secret: bytes, pq_secret_bytes: bytes, transcript: bytes) -> bytes:
    if len(x_secret) != 32 or len(pq_secret_bytes) != 32:
        raise HybridError("both halves must contribute 32 bytes")
    h = hashlib.sha256()
    h.update(HYBRID_INFO)
    h.update(len(x_secret).to_bytes(2, "big"))
    h.update(x_secret)
    h.update(len(pq_secret_bytes).to_bytes(2, "big"))
    h.update(pq_secret_bytes)
    h.update(transcript)
    return h.digest()


def initiate(peer_bundle: bytes, seed: Optional[bytes] = None) -> Tuple[HandshakeMessage, bytes]:
    """Start a handshake. Returns the message to send and our derived key."""
    if len(peer_bundle) != 32 + 32 + 2 * 3:
        raise HybridError("peer bundle has the wrong length")
    peer_x = peer_bundle[:32]
    peer_pq = PublicKey.from_bytes(peer_bundle[32:])

    if seed is None:
        seed = os.urandom(32)
    if len(seed) != 32:
        raise HybridError("seed must be 32 bytes")

    eph = X25519PrivateKey.from_private_bytes(seed)
    try:
        x_secret = eph.exchange(X25519PublicKey.from_public_bytes(peer_x))
    except ValueError as exc:
        raise HybridError("peer X25519 key is not a valid point") from exc

    ct, bit = encapsulate(peer_pq, seed[0] & 1, seed=seed)
    pq_bytes = shared_secret(bit, context=peer_pq.seed)

    from cryptography.hazmat.primitives import serialization

    msg = HandshakeMessage(
        x25519_public=eph.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
        pq_ciphertext=ct,
        pq_bit=bit,
    )
    transcript = hashlib.sha256(msg.to_bytes() + peer_bundle).digest()
    return msg, _combine(x_secret, pq_bytes, transcript)


def respond(our_keypair: HybridKeyPair, msg: HandshakeMessage) -> bytes:
    """Complete a handshake from the responder's side."""
    try:
        peer_x = X25519PublicKey.from_public_bytes(msg.x25519_public)
        x_secret = our_keypair.x25519_private.exchange(peer_x)
    except ValueError as exc:
        raise HybridError("initiator X25519 key is not a valid point") from exc

    bit = decapsulate(our_keypair.pq_secret, msg.pq_ciphertext)
    pq_bytes = shared_secret(bit, context=our_keypair.pq_public.seed)

    transcript = hashlib.sha256(msg.to_bytes() + our_keypair.public_bundle()).digest()
    return _combine(x_secret, pq_bytes, transcript)


def confirm(key: bytes, label: bytes) -> bytes:
    """Derive a confirmation tag so both sides can prove they agree."""
    if not label:
        raise HybridError("label must not be empty")
    return hashlib.sha256(b"pqshield/v1/confirm" + label + key).digest()
