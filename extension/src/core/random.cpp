/* Copyright 2026 ETF2L Contributors, Dave */
#include "random.h"

#include <psa/crypto.h>

namespace smcrypto {

Result<SecretBytes> RandomBytes(size_t size)
{
	SecretBytes bytes(size);
	psa_status_t status = psa_generate_random(bytes.data(), bytes.size());
	if (status != PSA_SUCCESS)
		return LibraryError{status, "psa_generate_random"};
	return bytes;
}

Result<int32_t> RandomInt(int32_t min, int32_t max)
{
	/* The number of values, up to 2^32 for the full range. */
	uint64_t span = static_cast<uint64_t>(static_cast<int64_t>(max) - static_cast<int64_t>(min)) + 1;
	/* The largest multiple of span that fits in 32 bits: draws at or above
	 * it are discarded so every value is equally likely. */
	constexpr uint64_t kDraws = uint64_t(1) << 32;
	uint64_t limit = kDraws - kDraws % span;
	for (;;) {
		uint8_t bytes[4];
		psa_status_t status = psa_generate_random(bytes, sizeof(bytes));
		if (status != PSA_SUCCESS)
			return LibraryError{status, "psa_generate_random"};
		uint64_t draw = (uint64_t(bytes[0]) << 24) | (uint64_t(bytes[1]) << 16) | (uint64_t(bytes[2]) << 8) | bytes[3];
		Wipe(bytes, sizeof(bytes));
		if (draw >= limit)
			continue;
		return static_cast<int32_t>(static_cast<int64_t>(min) + static_cast<int64_t>(draw % span));
	}
}

} // namespace smcrypto
