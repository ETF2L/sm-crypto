/* Copyright 2026 ETF2L Contributors, Dave */
#include "hash.h"

#include <psa/crypto.h>

namespace smcrypto {

namespace {

struct HashInfo {
	psa_algorithm_t algorithm;
	size_t size;
	bool isSupported;
	const char *name;
};

/* Whether the library was built with each hash, indexed by Hash: from its
 * PSA_WANT_ALG_* macros, since a later version may leave legacy hashes
 * out. */
constexpr bool kHas[kHashCount] = {
#ifdef PSA_WANT_ALG_SHA_256
	true,
#else
	false,
#endif
#ifdef PSA_WANT_ALG_SHA_224
	true,
#else
	false,
#endif
#ifdef PSA_WANT_ALG_SHA_384
	true,
#else
	false,
#endif
#ifdef PSA_WANT_ALG_SHA_512
	true,
#else
	false,
#endif
#ifdef PSA_WANT_ALG_SHA3_224
	true,
#else
	false,
#endif
#ifdef PSA_WANT_ALG_SHA3_256
	true,
#else
	false,
#endif
#ifdef PSA_WANT_ALG_SHA3_384
	true,
#else
	false,
#endif
#ifdef PSA_WANT_ALG_SHA3_512
	true,
#else
	false,
#endif
#ifdef PSA_WANT_ALG_SHA_1
	true,
#else
	false,
#endif
#ifdef PSA_WANT_ALG_MD5
	true,
#else
	false,
#endif
};

/* Indexed by Hash. */
const HashInfo kHashes[kHashCount] = {
	{PSA_ALG_SHA_256, 32, kHas[0], "SHA-256"},
	{PSA_ALG_SHA_224, 28, kHas[1], "SHA-224"},
	{PSA_ALG_SHA_384, 48, kHas[2], "SHA-384"},
	{PSA_ALG_SHA_512, 64, kHas[3], "SHA-512"},
	{PSA_ALG_SHA3_224, 28, kHas[4], "SHA3-224"},
	{PSA_ALG_SHA3_256, 32, kHas[5], "SHA3-256"},
	{PSA_ALG_SHA3_384, 48, kHas[6], "SHA3-384"},
	{PSA_ALG_SHA3_512, 64, kHas[7], "SHA3-512"},
	{PSA_ALG_SHA_1, 20, kHas[8], "SHA-1"},
	{PSA_ALG_MD5, 16, kHas[9], "MD5"},
};

const HashInfo &InfoOf(Hash hash)
{
	return kHashes[static_cast<int>(hash)];
}

} // namespace

bool IsHashSupported(Hash hash)
{
	return InfoOf(hash).isSupported;
}

size_t HashSize(Hash hash)
{
	return InfoOf(hash).size;
}

const char *HashName(Hash hash)
{
	return InfoOf(hash).name;
}

uint32_t HashAlgorithm(Hash hash)
{
	return InfoOf(hash).algorithm;
}

Result<Bytes> ComputeHash(Hash hash, ByteView data)
{
	Bytes digest(HashSize(hash));
	size_t length = 0;
	psa_status_t status =
		psa_hash_compute(InfoOf(hash).algorithm, data.data, data.size, digest.data(), digest.size(), &length);
	if (status != PSA_SUCCESS)
		return LibraryError{status, "psa_hash_compute"};
	return digest;
}

struct HashStream::Operation {
	psa_hash_operation_t psa = PSA_HASH_OPERATION_INIT;
	bool isActive = true;

	~Operation() { psa_hash_abort(&psa); }
};

HashStream::HashStream(Hash hash, std::unique_ptr<Operation> operation)
	: m_hash(hash), m_operation(std::move(operation))
{
}

HashStream::~HashStream() = default;

Result<std::unique_ptr<HashStream>> HashStream::Start(Hash hash)
{
	auto operation = std::make_unique<Operation>();
	psa_status_t status = psa_hash_setup(&operation->psa, InfoOf(hash).algorithm);
	if (status != PSA_SUCCESS)
		return LibraryError{status, "psa_hash_setup"};
	return std::unique_ptr<HashStream>(new HashStream(hash, std::move(operation)));
}

Status HashStream::Update(ByteView data)
{
	if (!m_operation->isActive)
		return LibraryError{PSA_ERROR_BAD_STATE, "psa_hash_update"};
	psa_status_t status = psa_hash_update(&m_operation->psa, data.data, data.size);
	if (status != PSA_SUCCESS) {
		m_operation->isActive = false;
		return LibraryError{status, "psa_hash_update"};
	}
	return Done{};
}

Result<Bytes> HashStream::Finish()
{
	if (!m_operation->isActive)
		return LibraryError{PSA_ERROR_BAD_STATE, "psa_hash_finish"};
	m_operation->isActive = false;
	Bytes digest(HashSize(m_hash));
	size_t length = 0;
	psa_status_t status = psa_hash_finish(&m_operation->psa, digest.data(), digest.size(), &length);
	if (status != PSA_SUCCESS)
		return LibraryError{status, "psa_hash_finish"};
	return digest;
}

} // namespace smcrypto
