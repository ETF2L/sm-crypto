/* Copyright 2026 ETF2L Contributors, Dave
 *
 * Sealed messages: authenticated encryption with a fresh random nonce per
 * message, in one self-describing byte string (docs/formats.md):
 *
 *   format (1 byte) | nonce (12 bytes) | ciphertext | tag (16 bytes)
 *
 * format names the cipher and the layout: 0x01 AES-256-GCM, 0x02
 * ChaCha20-Poly1305, 0x03 AES-128-GCM, each with a 12-byte nonce and a
 * 16-byte tag; a later format may have other sizes. The cipher
 * authenticates the format byte followed by the caller's additional data,
 * so neither can be changed unnoticed. The ciphertext is as long as the
 * plaintext. Main thread only (library.h). */
#ifndef SMCRYPTO_CORE_SEALED_H
#define SMCRYPTO_CORE_SEALED_H

#include "bytes.h"
#include "library.h"

#include <optional>

namespace smcrypto {

/* The values match CryptoCipher in smcrypto.inc; they never change. */
enum class Cipher {
	AES256GCM = 0,
	ChaCha20Poly1305 = 1,
	AES128GCM = 2,
};

constexpr int kCipherCount = 3;

/* Whether this build of the library has the cipher. */
bool IsCipherSupported(Cipher cipher);

/* The key size the cipher needs, in bytes. */
size_t CipherKeySize(Cipher cipher);

/* The nonce size of the cipher's format, in bytes. */
size_t SealedNonceSize(Cipher cipher);

/* What sealing with the cipher adds to the plaintext: format byte, nonce
 * and tag. */
size_t SealedOverhead(Cipher cipher);

/* "AES-256-GCM", ... */
const char *CipherName(Cipher cipher);

/* Seals plaintext with a random nonce. key must be CipherKeySize(cipher)
 * bytes long; another size throws std::invalid_argument. */
Result<Bytes> Seal(Cipher cipher, ByteView key, ByteView plaintext, ByteView aad);

/* Seal() with a given nonce of SealedNonceSize(cipher) bytes, for
 * known-answer tests; a key or nonce of another size throws
 * std::invalid_argument. A nonce must never be used twice with one key. */
Result<Bytes> SealWithNonce(Cipher cipher, ByteView key, ByteView nonce, ByteView plaintext, ByteView aad);

/* The plaintext of a sealed message, or nothing when it cannot be opened
 * with key and aad: it is too short, its format is unknown, the key's size
 * does not fit its cipher, or it or aad were changed. The reasons are not
 * told apart, so a caller cannot be used to probe. */
Result<std::optional<SecretBytes>> Open(ByteView key, ByteView sealed, ByteView aad);

} // namespace smcrypto

#endif // SMCRYPTO_CORE_SEALED_H
