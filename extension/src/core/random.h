/* Copyright 2026 ETF2L Contributors, Dave
 *
 * Random numbers from the library's CTR_DRBG (AES-256), seeded from the
 * system's entropy source (getrandom or /dev/urandom on Linux,
 * BCryptGenRandom on Windows) and reseeded by the library. Main thread only
 * (library.h). */
#ifndef SMCRYPTO_CORE_RANDOM_H
#define SMCRYPTO_CORE_RANDOM_H

#include "bytes.h"
#include "library.h"

namespace smcrypto {

/* size random bytes. */
Result<SecretBytes> RandomBytes(size_t size);

/* A uniformly distributed number from min to max, both included; min must
 * not be greater than max. */
Result<int32_t> RandomInt(int32_t min, int32_t max);

} // namespace smcrypto

#endif // SMCRYPTO_CORE_RANDOM_H
