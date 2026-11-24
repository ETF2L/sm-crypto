/* Copyright 2026 ETF2L Contributors, Dave
 *
 * Hash functions: one-shot and as a stream of updates. HashStream is the
 * only part of the core the worker thread uses (see library.h). */
#ifndef SMCRYPTO_CORE_HASH_H
#define SMCRYPTO_CORE_HASH_H

#include "bytes.h"
#include "library.h"

#include <memory>

namespace smcrypto {

/* The values match CryptoHash in smcrypto.inc; they never change. */
enum class Hash {
	SHA256 = 0,
	SHA224 = 1,
	SHA384 = 2,
	SHA512 = 3,
	SHA3_224 = 4,
	SHA3_256 = 5,
	SHA3_384 = 6,
	SHA3_512 = 7,
	SHA1 = 8, /* legacy: collisions are practical */
	MD5 = 9,  /* legacy: collisions are trivial */
};

constexpr int kHashCount = 10;

/* The largest digest, SHA-512's and SHA3-512's. */
constexpr size_t kMaxHashSize = 64;

/* Whether this build of the library has the hash. */
bool IsHashSupported(Hash hash);

/* The digest's size in bytes. */
size_t HashSize(Hash hash);

/* "SHA-256", "SHA3-512", ... */
const char *HashName(Hash hash);

/* The PSA algorithm identifier, for the other parts of the core. */
uint32_t HashAlgorithm(Hash hash);

Result<Bytes> ComputeHash(Hash hash, ByteView data);

/* A hash fed in pieces. Finish() ends it; after that, and after any failed
 * call, every call fails with PSA_ERROR_BAD_STATE. */
class HashStream {
public:
	static Result<std::unique_ptr<HashStream>> Start(Hash hash);
	~HashStream();

	HashStream(const HashStream &) = delete;
	HashStream &operator=(const HashStream &) = delete;

	Status Update(ByteView data);
	Result<Bytes> Finish();

private:
	struct Operation;
	HashStream(Hash hash, std::unique_ptr<Operation> operation);

	Hash m_hash;
	std::unique_ptr<Operation> m_operation;
};

} // namespace smcrypto

#endif // SMCRYPTO_CORE_HASH_H
