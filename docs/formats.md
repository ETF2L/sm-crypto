# Formats

What SMCrypto writes, for reading and writing it outside SourceMod.

## Sealed messages

`CryptoKey.Seal` writes one byte string, then encodes it (base64 by default):

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | Format: `0x01` AES-256-GCM, `0x02` ChaCha20-Poly1305, `0x03` AES-128-GCM |
| 1 | 12 | Nonce, random per message |
| 13 | n | Ciphertext, as long as the plaintext |
| 13 + n | 16 | Authentication tag |

The cipher authenticates the format byte followed by the additional data the plugin passed (`aad`, empty for none):
AEAD additional data = `format || aad`. The format byte is thereby bound to the message, so it cannot be changed to
make the message be read with another cipher. With each of these formats a sealed message is 29 bytes longer than its
plaintext (`CRYPTO_SEAL_OVERHEAD`).

Format bytes are never reused for another layout; a later format gets a new byte, and `Open` keeps reading the old
ones.

### Reading one in Python

With the [cryptography](https://cryptography.io/) package:

```python
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

CIPHERS = {1: AESGCM, 2: ChaCha20Poly1305, 3: AESGCM}

def open_sealed(key: bytes, text: str, aad: bytes = b"") -> bytes:
    sealed = base64.b64decode(text, validate=True)
    form, nonce, rest = sealed[0], sealed[1:13], sealed[13:]
    return CIPHERS[form](key).decrypt(nonce, rest, bytes([form]) + aad)   # raises InvalidTag when changed

def seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> str:
    import os
    form, nonce = 1, os.urandom(12)                                       # AES-256-GCM, a 32-byte key
    return base64.b64encode(bytes([form]) + nonce + AESGCM(key).encrypt(nonce, plaintext, bytes([form]) + aad)).decode()
```

The unit tests check the extension against vectors made by `extension/tests/tools/sealed_vectors.py`.

## Derived keys

`key.Derive(info, length, salt, hash)` is HKDF (RFC 5869) with the key's bytes as input keying material. An empty salt
is no salt, which HKDF treats as a salt of zero bytes as long as a digest of the hash. In Python:

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

derived = HKDF(hashes.SHA256(), 32, salt=None, info=b"myplugin tokens v1").derive(master_key)
```

## Keys

`CryptoKey.Export` writes the key's bytes as they are, in the encoding asked for; `Import` reads them back. A key made
with `FromString` is the string's bytes, as an HMAC library on a web site takes a text secret.

## Encodings

Hex is lowercase on output and either case on input. Base64 and base64url follow RFC 4648 sections 4 and 5; base64
is always padded, base64url never. Decoding refuses whitespace and non-canonical text.
