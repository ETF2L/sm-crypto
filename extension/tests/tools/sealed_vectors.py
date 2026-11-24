#!/usr/bin/env python3
# Copyright 2026 ETF2L Contributors, Dave
#
# Writes the known-answer vectors of sealed messages in sealed_tests.cpp
# with an independent implementation (Python's cryptography package):
#   python3 -I sealed_vectors.py
# A sealed message is format | nonce | ciphertext | tag, and the cipher
# authenticates the format byte followed by the additional data.
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

CASES = [
    ('AES256GCM', 0x01, AESGCM, bytes(range(32))),
    ('ChaCha20Poly1305', 0x02, ChaCha20Poly1305, bytes(range(32, 64))),
    ('AES128GCM', 0x03, AESGCM, bytes(range(16))),
]
NONCE = bytes(range(100, 112))
INPUTS = [(b'', b''), (b'SMCrypto sealed message', b''), (b'SMCrypto sealed message', b'STEAM_0:1:23')]

for name, form, cipher, key in CASES:
    for plaintext, aad in INPUTS:
        sealed = bytes([form]) + NONCE + cipher(key).encrypt(NONCE, plaintext, bytes([form]) + aad)
        print(f'\t{{Cipher::{name}, "{key.hex()}", "{plaintext.decode()}", "{aad.decode()}",\n\t "{sealed.hex()}"}},')
