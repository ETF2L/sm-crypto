/* Copyright 2026 ETF2L Contributors, Dave
 *
 * Everything of Mbed TLS outside its PSA Crypto API lives in this file:
 * the version, freeing the library's state and wiping memory. A move to
 * another major version (Mbed TLS 4 puts the crypto library into
 * TF-PSA-Crypto) starts here; the rest of the core only calls PSA. */
#include "bytes.h"
#include "library.h"

#include <mbedtls/build_info.h>
#include <mbedtls/platform_util.h>
#include <psa/crypto.h>

#include <cstdio>

#if MBEDTLS_VERSION_MAJOR != 3
#error "SMCrypto is built for Mbed TLS 3; check library.cpp and docs/development.md before moving on"
#endif

namespace smcrypto {

namespace {

const char *StatusName(int32_t status)
{
	switch (status) {
	case PSA_SUCCESS: return "PSA_SUCCESS";
	case PSA_ERROR_GENERIC_ERROR: return "PSA_ERROR_GENERIC_ERROR";
	case PSA_ERROR_NOT_SUPPORTED: return "PSA_ERROR_NOT_SUPPORTED";
	case PSA_ERROR_NOT_PERMITTED: return "PSA_ERROR_NOT_PERMITTED";
	case PSA_ERROR_BUFFER_TOO_SMALL: return "PSA_ERROR_BUFFER_TOO_SMALL";
	case PSA_ERROR_ALREADY_EXISTS: return "PSA_ERROR_ALREADY_EXISTS";
	case PSA_ERROR_DOES_NOT_EXIST: return "PSA_ERROR_DOES_NOT_EXIST";
	case PSA_ERROR_BAD_STATE: return "PSA_ERROR_BAD_STATE";
	case PSA_ERROR_INVALID_ARGUMENT: return "PSA_ERROR_INVALID_ARGUMENT";
	case PSA_ERROR_INSUFFICIENT_MEMORY: return "PSA_ERROR_INSUFFICIENT_MEMORY";
	case PSA_ERROR_INSUFFICIENT_STORAGE: return "PSA_ERROR_INSUFFICIENT_STORAGE";
	case PSA_ERROR_COMMUNICATION_FAILURE: return "PSA_ERROR_COMMUNICATION_FAILURE";
	case PSA_ERROR_STORAGE_FAILURE: return "PSA_ERROR_STORAGE_FAILURE";
	case PSA_ERROR_HARDWARE_FAILURE: return "PSA_ERROR_HARDWARE_FAILURE";
	case PSA_ERROR_CORRUPTION_DETECTED: return "PSA_ERROR_CORRUPTION_DETECTED";
	case PSA_ERROR_INSUFFICIENT_ENTROPY: return "PSA_ERROR_INSUFFICIENT_ENTROPY";
	case PSA_ERROR_INVALID_SIGNATURE: return "PSA_ERROR_INVALID_SIGNATURE";
	case PSA_ERROR_INVALID_PADDING: return "PSA_ERROR_INVALID_PADDING";
	case PSA_ERROR_INSUFFICIENT_DATA: return "PSA_ERROR_INSUFFICIENT_DATA";
	case PSA_ERROR_INVALID_HANDLE: return "PSA_ERROR_INVALID_HANDLE";
	case PSA_ERROR_DATA_CORRUPT: return "PSA_ERROR_DATA_CORRUPT";
	case PSA_ERROR_DATA_INVALID: return "PSA_ERROR_DATA_INVALID";
	default: return "an unknown PSA status";
	}
}

} // namespace

std::string LibraryError::Describe() const
{
	char text[160];
	snprintf(text, sizeof(text), "%s failed: %s (%d)", function, StatusName(status), static_cast<int>(status));
	return text;
}

Status InitializeLibrary()
{
	psa_status_t status = psa_crypto_init();
	if (status != PSA_SUCCESS)
		return LibraryError{status, "psa_crypto_init"};
	return Done{};
}

void ShutdownLibrary()
{
	mbedtls_psa_crypto_free();
}

const char *LibraryVersion()
{
	return "Mbed TLS " MBEDTLS_VERSION_STRING;
}

void Wipe(void *data, size_t size)
{
	if (data && size > 0)
		mbedtls_platform_zeroize(data, size);
}

} // namespace smcrypto
