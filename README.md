# PostQuantum Shield

Hybrid key agreement that combines X25519 with a learning-with-errors KEM, so
an attacker has to break **both** primitives to recover the session key.

## Why hybrid

You do not have to bet on either primitive. If a quantum computer eventually
breaks X25519, the lattice half still holds. If the lattice scheme falls to a
classical attack, X25519 still holds. The two secrets are concatenated and run
through one KDF, so neither alone is enough.

## What is implemented

**The LWE KEM** (`pqshield/kem.py`) is written from the mathematics, not
wrapped from a library:

- modulus `q = 3329`, dimension `k = 3`, noise `eta = 2`
- public matrix `A` expanded deterministically from a 32-byte seed, so the
  public key stays short
- centred-binomial noise sampling, the same choice the Kyber designers made
  because it avoids floating point
- `t = A·s + e` for keygen, `u = Aᵀ·r + e1`, `v = tᵀ·r + e2 + encode(m)` for
  encapsulation, `decode(v − sᵀ·u)` for decapsulation

**The hybrid handshake** (`pqshield/hybrid.py`) binds both halves to a
transcript hash, so a replayed or spliced handshake derives a different key and
fails to authenticate.

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

## Run the tests

```bash
python -m pytest -q
```

## Use it

```python
from pqshield import HybridKeyPair, initiate, respond, confirm

server = HybridKeyPair.generate()

# client side
msg, client_key = initiate(server.public_bundle())

# server side
server_key = respond(server, msg)

assert client_key == server_key
assert confirm(client_key, b"client") == confirm(server_key, b"client")
```

## Honest scope

This is a **teaching and integration** implementation, not a production
replacement for ML-KEM. Specifically:

- it is **not constant-time**; the arithmetic uses Python integers and would
  leak through timing on a shared machine
- the parameters are deliberately small so the tests run in milliseconds; the
  security level is far below ML-KEM-768
- it encapsulates **one bit** per ciphertext, where ML-KEM encapsulates a
  256-bit key

What it does give you is a real, testable post-quantum half for a hybrid
handshake, with the correctness argument written down and the failure modes
covered by tests. For production, use `liboqs` or a vetted ML-KEM
implementation and keep this as the reference for how the hybrid combination
is meant to work.

## A bug worth recording

The first version of `keygen` computed the public vector with a generator
expression nested inside a list comprehension:

```python
t = [(a[i][j] * s[j] for j in range(K)) for i in range(K)]
t_vec = [sum(row) % Q for row in t]
```

The inner generators are consumed *after* the outer loop has finished, so
every row read the final value of `i` and the public key collapsed to one
repeated entry. The round-trip test caught it immediately. The fix computes
each row eagerly. This is the classic late-binding closure trap, and it is
exactly the kind of thing that only shows up when you actually run the maths.

## Layout

```
pqshield/
  kem.py      LWE key encapsulation
  hybrid.py   X25519 + LWE handshake
tests/
  test_kem.py
  test_hybrid.py
```

## Licence

MIT. See `LICENSE`.

## Author

Konain Sultan Khan (KK) — https://github.com/kkcyber2
LinkedIn: _add your profile URL here_
