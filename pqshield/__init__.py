"""PostQuantum Shield — hybrid X25519 + LWE key agreement."""

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
from .hybrid import (
    HandshakeMessage,
    HybridError,
    HybridKeyPair,
    confirm,
    initiate,
    respond,
)

__version__ = "1.0.0"

__all__ = [
    "Ciphertext",
    "PQError",
    "PublicKey",
    "SecretKey",
    "decapsulate",
    "encapsulate",
    "keygen",
    "shared_secret",
    "HandshakeMessage",
    "HybridError",
    "HybridKeyPair",
    "confirm",
    "initiate",
    "respond",
]
