/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The operations that take a key: HMAC (RFC 2104), HKDF (RFC 5869) and the
 * sealed messages of authenticated encryption (sealed.h). Keys are plain
 * byte strings here; CryptoKey handles hold them in the extension. Main
 * thread only (library.h). */
#ifndef SMCRYPTO_CORE_KEYED_H
#define SMCRYPTO_CORE_KEYED_H

#include "bytes.h"
#include "hash.h"
#include "library.h"

#include <memory>

namespace smcrypto {

/* The sizes a key may have, in bytes. */
constexpr size_t kMinKeySize = 1;
constexpr size_t kMaxKeySize = 1024;

Result<Bytes> ComputeHmac(Hash hash, ByteView key, ByteView message);

/* Whether mac is the HMAC of message, compared in constant time; a mac of
 * another length is not. */
Result<bool> VerifyHmac(Hash hash, ByteView key, ByteView message, ByteView mac);

/* An HMAC fed in pieces, like HashStream. It holds its key in the library's
 * key store until it is destroyed. */
class MacStream {
public:
	static Result<std::unique_ptr<MacStream>> Start(Hash hash, ByteView key);
	~MacStream();

	MacStream(const MacStream &) = delete;
	MacStream &operator=(const MacStream &) = delete;

	Status Update(ByteView data);
	Result<Bytes> Finish();

private:
	struct Operation;
	MacStream(Hash hash, std::unique_ptr<Operation> operation);

	Hash m_hash;
	std::unique_ptr<Operation> m_operation;
};

/* The most bytes HKDF derives with hash: 255 of its digests. */
size_t MaxHkdfLength(Hash hash);

/* HKDF-Extract and -Expand: length bytes from secret, salt (empty: none,
 * which is the same as a digest of zeros) and info. length must be 1 to
 * MaxHkdfLength(hash). */
Result<SecretBytes> DeriveHkdf(Hash hash, ByteView secret, ByteView salt, ByteView info, size_t length);

} // namespace smcrypto

#endif // SMCRYPTO_CORE_KEYED_H
