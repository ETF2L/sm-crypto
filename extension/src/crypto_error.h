/* Copyright 2026 ETF2L Contributors, Dave
 *
 * CryptoError of smcrypto.inc: what a file job's callback is told. Its
 * values are the plugin API's and never change; the core's FileError maps
 * to it. */
#ifndef SMCRYPTO_CRYPTO_ERROR_H
#define SMCRYPTO_CRYPTO_ERROR_H

#include "file_hash.h"

#include <cstdint>

enum class CryptoError : int32_t {
	None = 0,
	NotFound = 1,
	NotAFile = 2,
	Open = 3,
	Read = 4,
	Cancelled = 5,
	Internal = 6,
	InvalidPath = 7,
};

constexpr int kCryptoErrorCount = 8;

CryptoError CryptoErrorOf(smcrypto::FileError error);

/* "CryptoError_NotFound", ... */
const char *CryptoErrorName(CryptoError error);

#endif // SMCRYPTO_CRYPTO_ERROR_H
