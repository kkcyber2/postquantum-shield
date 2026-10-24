"""Tests for the LWE key encapsulation mechanism."""

import os

import pytest

from pqshield.kem import (
    Ciphertext,
    K,
    PQError,
    PublicKey,
    Q,
    SecretKey,
    decapsulate,
    encapsulate,
    keygen,
    shared_secret,
    _cbd,
    _decode,
    _encode_bit,
    _matrix_from_seed,
)


def test_keygen_is_deterministic_for_a_seed():
    seed = os.urandom(32)
    p1, s1 = keygen(seed)
    p2, s2 = keygen(seed)
    assert p1.to_bytes() == p2.to_bytes()
    assert s1.s == s2.s


def test_keygen_differs_across_seeds():
    p1, _ = keygen(os.urandom(32))
    p2, _ = keygen(os.urandom(32))
    assert p1.to_bytes() != p2.to_bytes()


def test_keygen_rejects_bad_seed():
    with pytest.raises(PQError):
        keygen(b"short")


def test_encapsulate_decapsulate_roundtrip_bit_zero():
    pub, sec = keygen(os.urandom(32))
    ct, bit = encapsulate(pub, 0, seed=os.urandom(32))
    assert bit == 0
    assert decapsulate(sec, ct) == 0


def test_encapsulate_decapsulate_roundtrip_bit_one():
    pub, sec = keygen(os.urandom(32))
    ct, bit = encapsulate(pub, 1, seed=os.urandom(32))
    assert bit == 1
    assert decapsulate(sec, ct) == 1


def test_roundtrip_holds_over_many_random_instances():
    """The noise bound must hold across many independent keypairs."""
    for _ in range(40):
        pub, sec = keygen(os.urandom(32))
        for bit in (0, 1):
            ct, _ = encapsulate(pub, bit, seed=os.urandom(32))
            assert decapsulate(sec, ct) == bit


def test_ciphertext_differs_for_same_message():
    pub, _ = keygen(os.urandom(32))
    a, _ = encapsulate(pub, 1, seed=os.urandom(32))
    b, _ = encapsulate(pub, 1, seed=os.urandom(32))
    assert a.to_bytes() != b.to_bytes()


def test_wrong_secret_key_usually_fails():
    """A different key must not reliably recover the bit.

    Aggregated over many keypairs, because at these toy parameters a secret
    key can legitimately be all-zero (roughly 5% of the time with eta=2 and
    k=3). Such a key contributes no noise, so a wrong key happens to agree
    with it. That is a property of the small parameter set, not a defect, and
    a single-keypair assertion would be flaky because of it.
    """
    trials = 0
    wrong = 0
    for _ in range(20):
        pub, _ = keygen(os.urandom(32))
        _, other = keygen(os.urandom(32))
        for _ in range(10):
            ct, b = encapsulate(pub, 1, seed=os.urandom(32))
            trials += 1
            if decapsulate(other, ct) != b:
                wrong += 1
    rate = wrong / trials
    # Chance is 0.5. A working scheme sits near it; a broken one would be 0.
    assert 0.30 <= rate <= 0.70, "wrong-key agreement rate was %.2f" % rate


def test_public_key_serialisation_roundtrip():
    pub, _ = keygen(os.urandom(32))
    back = PublicKey.from_bytes(pub.to_bytes())
    assert back.seed == pub.seed
    assert back.t == pub.t


def test_public_key_rejects_wrong_length():
    with pytest.raises(PQError):
        PublicKey.from_bytes(b"short")


def test_ciphertext_serialisation_roundtrip():
    pub, _ = keygen(os.urandom(32))
    ct, _ = encapsulate(pub, 1, seed=os.urandom(32))
    back = Ciphertext.from_bytes(ct.to_bytes())
    assert back.u == ct.u
    assert back.v == ct.v


def test_ciphertext_rejects_wrong_length():
    with pytest.raises(PQError):
        Ciphertext.from_bytes(b"short")


def test_decapsulate_rejects_wrong_dimension():
    _, sec = keygen(os.urandom(32))
    with pytest.raises(PQError):
        decapsulate(sec, Ciphertext(u=[1, 2], v=3))


def test_tampered_ciphertext_changes_the_bit():
    """Flipping the encoded half must flip the recovered bit."""
    pub, sec = keygen(os.urandom(32))
    ct, bit = encapsulate(pub, 0, seed=os.urandom(32))
    ct.v = (ct.v + Q // 2) % Q
    assert decapsulate(sec, ct) == 1 - bit


def test_shared_secret_is_deterministic():
    assert shared_secret(1, b"ctx") == shared_secret(1, b"ctx")


def test_shared_secret_depends_on_context():
    assert shared_secret(1, b"a") != shared_secret(1, b"b")


def test_shared_secret_depends_on_bit():
    assert shared_secret(0, b"ctx") != shared_secret(1, b"ctx")


def test_shared_secret_rejects_bad_bit():
    with pytest.raises(PQError):
        shared_secret(2)


def test_shared_secret_is_32_bytes():
    assert len(shared_secret(1)) == 32


def test_cbd_output_is_small_and_centred():
    samples = _cbd(os.urandom(32), 0, 200)
    assert all(-2 <= x <= 2 for x in samples)
    assert abs(sum(samples)) < 200


def test_cbd_is_deterministic():
    seed = os.urandom(32)
    assert _cbd(seed, 7, 50) == _cbd(seed, 7, 50)


def test_cbd_nonce_changes_output():
    seed = os.urandom(32)
    assert _cbd(seed, 1, 50) != _cbd(seed, 2, 50)


def test_matrix_expansion_is_deterministic_and_in_range():
    seed = os.urandom(32)
    a = _matrix_from_seed(seed, K)
    b = _matrix_from_seed(seed, K)
    assert a == b
    assert len(a) == K and all(len(row) == K for row in a)
    assert all(0 <= x < Q for row in a for x in row)


def test_encode_decode_are_inverse():
    assert _decode(_encode_bit(0)) == 0
    assert _decode(_encode_bit(1)) == 1


def test_encode_rejects_non_bit():
    with pytest.raises(PQError):
        _encode_bit(2)


def test_decode_rounds_near_zero_to_zero():
    assert _decode(1) == 0
    assert _decode(Q - 1) == 0


def test_decode_rounds_near_half_to_one():
    assert _decode(Q // 2) == 1
    assert _decode(Q // 2 + 3) == 1
