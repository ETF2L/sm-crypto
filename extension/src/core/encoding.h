/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The text forms of binary values: lowercase hex, base64 and base64url
 * (RFC 4648), and Raw, the bytes themselves. Decoding is strict, so every
 * value has exactly one accepted text (hex digits may be either case): a
 * decoded value cannot be changed by rewriting its text. Results are
 * SecretBytes because the values may be keys or plaintexts. */
#ifndef SMCRYPTO_CORE_ENCODING_H
#define SMCRYPTO_CORE_ENCODING_H

#include "bytes.h"

#include <optional>

namespace smcrypto {

/* The values match CryptoEncoding in smcrypto.inc. */
enum class Encoding {
	Hex = 0,       /* two lowercase hex digits per byte */
	Base64 = 1,    /* RFC 4648 section 4, padded with "=" */
	Base64Url = 2, /* RFC 4648 section 5, without padding */
	Raw = 3,       /* the bytes as they are */
};

constexpr int kEncodingCount = 4;

/* The length of the encoded form of size bytes, without a terminator; in
 * 64 bits, so it cannot wrap for any size a plugin or a file can have. */
uint64_t EncodedLength(uint64_t size, Encoding encoding);

/* The encoded form of bytes. */
SecretBytes Encode(ByteView bytes, Encoding encoding);

/* The bytes text encodes, or nothing when it is not exactly one value's
 * text: an odd number or a wrong hex digit; for base64 a wrong character,
 * length or padding, padding inside, or bits beyond the value that are not
 * zero; for base64url the same without any padding. */
std::optional<SecretBytes> Decode(ByteView text, Encoding encoding);

} // namespace smcrypto

#endif // SMCRYPTO_CORE_ENCODING_H
