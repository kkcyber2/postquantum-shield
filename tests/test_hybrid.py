"""Tests for the hybrid X25519 + LWE handshake."""

import os

import pytest

from pqshield.hybrid import (
    HandshakeMessage,
    HybridError,
    HybridKeyPair,
    confirm,
    initiate,
    respond,
)


def test_hybrid_keypair_is_deterministic_for_a_seed():
    seed = os.urandom(32)
    a = HybridKeyPair.generate(seed)
    b = HybridKeyPair.generate(seed)
    assert a.public_bundle() == b.public_bundle()


def test_hybrid_keypair_rejects_bad_seed():
    with pytest.raises(HybridError):
        HybridKeyPair.generate(b"short")


def test_handshake_agrees_on_the_same_key():
    server = HybridKeyPair.generate()
    msg, client_key = initiate(server.public_bundle())
    server_key = respond(server, msg)
    assert client_key == server_key
    assert len(client_key) == 32


def test_handshake_agrees_across_many_instances():
    for _ in range(25):
        server = HybridKeyPair.generate()
        msg, ck = initiate(server.public_bundle())
        sk = respond(server, msg)
        assert ck == sk


def test_different_servers_produce_different_keys():
    s1 = HybridKeyPair.generate()
    s2 = HybridKeyPair.generate()
    m1, k1 = initiate(s1.public_bundle())
    m2, k2 = initiate(s2.public_bundle())
    assert k1 != k2
    assert respond(s1, m1) == k1
    assert respond(s2, m2) == k2


def test_handshake_message_serialisation_roundtrip():
    server = HybridKeyPair.generate()
    msg, _ = initiate(server.public_bundle())
    back = HandshakeMessage.from_bytes(msg.to_bytes())
    assert back.x25519_public == msg.x25519_public
    assert back.pq_ciphertext.u == msg.pq_ciphertext.u
    assert back.pq_ciphertext.v == msg.pq_ciphertext.v
    assert back.pq_bit == msg.pq_bit


def test_handshake_message_rejects_wrong_length():
    with pytest.raises(HybridError):
        HandshakeMessage.from_bytes(b"short")


def test_handshake_message_rejects_invalid_bit():
    server = HybridKeyPair.generate()
    msg, _ = initiate(server.public_bundle())
    raw = bytearray(msg.to_bytes())
    raw[-1] = 9
    with pytest.raises(HybridError):
        HandshakeMessage.from_bytes(bytes(raw))


def test_initiate_rejects_bad_bundle_length():
    with pytest.raises(HybridError):
        initiate(b"short")


def test_initiate_rejects_invalid_x25519_point():
    server = HybridKeyPair.generate()
    bundle = bytearray(server.public_bundle())
    bundle[0:32] = b"\x00" * 32  # low-order point
    with pytest.raises(HybridError):
        initiate(bytes(bundle))


def test_respond_rejects_invalid_initiator_point():
    server = HybridKeyPair.generate()
    msg, _ = initiate(server.public_bundle())
    msg.x25519_public = b"\x00" * 32
    with pytest.raises(HybridError):
        respond(server, msg)


def test_tampered_ciphertext_breaks_agreement():
    """If the PQ half is altered, the two sides must not agree."""
    server = HybridKeyPair.generate()
    msg, client_key = initiate(server.public_bundle())
    msg.pq_ciphertext.v = (msg.pq_ciphertext.v + 1664) % 3329
    server_key = respond(server, msg)
    assert server_key != client_key


def test_transcript_binding_rejects_spliced_handshake():
    """A message replayed against a different server must not agree."""
    s1 = HybridKeyPair.generate()
    s2 = HybridKeyPair.generate()
    msg, client_key = initiate(s1.public_bundle())
    # The same message answered by a different server derives a different key.
    other_key = respond(s2, msg)
    assert other_key != client_key


def test_confirm_tags_match_when_keys_match():
    server = HybridKeyPair.generate()
    msg, ck = initiate(server.public_bundle())
    sk = respond(server, msg)
    assert confirm(ck, b"client") == confirm(sk, b"client")


def test_confirm_tags_differ_by_label():
    key = os.urandom(32)
    assert confirm(key, b"client") != confirm(key, b"server")


def test_confirm_rejects_empty_label():
    with pytest.raises(HybridError):
        confirm(os.urandom(32), b"")


def test_public_bundle_has_expected_length():
    server = HybridKeyPair.generate()
    assert len(server.public_bundle()) == 32 + 32 + 2 * 3


def test_x25519_public_is_32_bytes():
    server = HybridKeyPair.generate()
    assert len(server.x25519_public_bytes()) == 32
