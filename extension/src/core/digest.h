/* Copyright 2026 ETF2L Contributors, Dave
 *
 * A digest fed in pieces: a hash or an HMAC, as CryptoDigest handles hold
 * it. Main thread only (library.h). */
#ifndef SMCRYPTO_CORE_DIGEST_H
#define SMCRYPTO_CORE_DIGEST_H

#include "hash.h"
#include "keyed.h"

#include <memory>

namespace smcrypto {

class Digest {
public:
	static Result<std::unique_ptr<Digest>> StartHash(Hash hash);
	static Result<std::unique_ptr<Digest>> StartHmac(Hash hash, ByteView key);

	Hash GetHash() const { return m_hash; }
	bool IsHmac() const { return m_mac != nullptr; }
	/* Whether Finish() was called or an Update() failed. */
	bool IsFinished() const { return m_isFinished; }

	Status Update(ByteView data);
	/* Ends the digest and returns it; an unfinished digest only. */
	Result<Bytes> Finish();

private:
	Digest(Hash hash, std::unique_ptr<HashStream> hashStream, std::unique_ptr<MacStream> macStream);

	Hash m_hash;
	std::unique_ptr<HashStream> m_plain;
	std::unique_ptr<MacStream> m_mac;
	bool m_isFinished = false;
};

} // namespace smcrypto

#endif // SMCRYPTO_CORE_DIGEST_H
