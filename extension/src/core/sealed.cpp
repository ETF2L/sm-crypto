/* Copyright 2026 ETF2L Contributors, Dave */
#include "sealed.h"
#include "psa_key.h"
#include "random.h"

#include <psa/crypto.h>

#include <algorithm>
#include <cstdio>
#include <stdexcept>

namespace smcrypto {

namespace {

#if defined(PSA_WANT_ALG_GCM) && defined(PSA_WANT_KEY_TYPE_AES)
constexpr bool kHasAesGcm = true;
#else
constexpr bool kHasAesGcm = false;
#endif
#if defined(PSA_WANT_ALG_CHACHA20_POLY1305) && defined(PSA_WANT_KEY_TYPE_CHACHA20)
constexpr bool kHasChaChaPoly = true;
#else
constexpr bool kHasChaChaPoly = false;
#endif

/* A format: its byte, cipher and sizes. A new format is a new row with a
 * byte never used before. */
struct CipherInfo {
	uint8_t format;
	psa_key_type_t keyType;
	psa_algorithm_t algorithm;
	size_t keySize;
	size_t nonceSize;
	size_t tagSize;
	bool isSupported;
	const char *name;
};

/* Indexed by Cipher. */
const CipherInfo kCiphers[kCipherCount] = {
	{0x01, PSA_KEY_TYPE_AES, PSA_ALG_GCM, 32, 12, 16, kHasAesGcm, "AES-256-GCM"},
	{0x02, PSA_KEY_TYPE_CHACHA20, PSA_ALG_CHACHA20_POLY1305, 32, 12, 16, kHasChaChaPoly, "ChaCha20-Poly1305"},
	{0x03, PSA_KEY_TYPE_AES, PSA_ALG_GCM, 16, 12, 16, kHasAesGcm, "AES-128-GCM"},
};

size_t OverheadOf(const CipherInfo &info)
{
	return 1 + info.nonceSize + info.tagSize;
}

const CipherInfo &InfoOf(Cipher cipher)
{
	return kCiphers[static_cast<int>(cipher)];
}

std::optional<Cipher> CipherOfFormat(uint8_t format)
{
	for (int i = 0; i < kCipherCount; i++)
		if (kCiphers[i].format == format)
			return static_cast<Cipher>(i);
	return std::nullopt;
}

/* What the cipher authenticates besides the ciphertext. */
Bytes AuthenticatedData(uint8_t format, ByteView aad)
{
	Bytes data;
	data.reserve(1 + aad.size);
	data.push_back(format);
	data.insert(data.end(), aad.data, aad.data + aad.size);
	return data;
}

Result<ImportedKey> ImportCipherKey(const CipherInfo &info, ByteView key, psa_key_usage_t usage)
{
	return ImportedKey::Import(info.keyType, info.algorithm, usage, key);
}

} // namespace

bool IsCipherSupported(Cipher cipher)
{
	return InfoOf(cipher).isSupported;
}

size_t CipherKeySize(Cipher cipher)
{
	return InfoOf(cipher).keySize;
}

size_t SealedNonceSize(Cipher cipher)
{
	return InfoOf(cipher).nonceSize;
}

size_t SealedOverhead(Cipher cipher)
{
	return OverheadOf(InfoOf(cipher));
}

const char *CipherName(Cipher cipher)
{
	return InfoOf(cipher).name;
}

Result<Bytes> Seal(Cipher cipher, ByteView key, ByteView plaintext, ByteView aad)
{
	Result<SecretBytes> nonce = RandomBytes(SealedNonceSize(cipher));
	if (!nonce.IsOk())
		return nonce.Error();
	return SealWithNonce(cipher, key, nonce.Value(), plaintext, aad);
}

Result<Bytes> SealWithNonce(Cipher cipher, ByteView key, ByteView nonce, ByteView plaintext, ByteView aad)
{
	const CipherInfo &info = InfoOf(cipher);
	/* The library would take a 16-byte key for AES-256-GCM as AES-128. A
	 * wrong size is the caller's bug, not a failure of the library. */
	if (key.size != info.keySize || nonce.size != info.nonceSize) {
		char reason[160];
		snprintf(reason, sizeof(reason), "%s needs a key of %zu bytes and a nonce of %zu, not %zu and %zu",
		         info.name, info.keySize, info.nonceSize, key.size, nonce.size);
		throw std::invalid_argument(reason);
	}
	Result<ImportedKey> imported = ImportCipherKey(info, key, PSA_KEY_USAGE_ENCRYPT);
	if (!imported.IsOk())
		return imported.Error();

	Bytes sealed(OverheadOf(info) + plaintext.size);
	sealed[0] = info.format;
	std::copy(nonce.data, nonce.data + info.nonceSize, sealed.begin() + 1);
	Bytes authenticated = AuthenticatedData(info.format, aad);
	uint8_t *output = sealed.data() + 1 + info.nonceSize;
	size_t outputSize = plaintext.size + info.tagSize;
	size_t written = 0;
	psa_status_t status = psa_aead_encrypt(imported.Value().Id(), info.algorithm, nonce.data, info.nonceSize,
	                                       authenticated.data(), authenticated.size(), plaintext.data, plaintext.size,
	                                       output, outputSize, &written);
	if (status != PSA_SUCCESS)
		return LibraryError{status, "psa_aead_encrypt"};
	if (written != outputSize)
		return LibraryError{PSA_ERROR_CORRUPTION_DETECTED, "psa_aead_encrypt"};
	return sealed;
}

Result<std::optional<SecretBytes>> Open(ByteView key, ByteView sealed, ByteView aad)
{
	std::optional<SecretBytes> notOpened;
	if (sealed.empty())
		return notOpened;
	std::optional<Cipher> cipher = CipherOfFormat(sealed.data[0]);
	if (!cipher)
		return notOpened;
	const CipherInfo &info = InfoOf(*cipher);
	if (!info.isSupported || sealed.size < OverheadOf(info) || key.size != info.keySize)
		return notOpened;

	Result<ImportedKey> imported = ImportCipherKey(info, key, PSA_KEY_USAGE_DECRYPT);
	if (!imported.IsOk())
		return imported.Error();
	Bytes authenticated = AuthenticatedData(info.format, aad);
	const uint8_t *nonce = sealed.data + 1;
	const uint8_t *input = nonce + info.nonceSize;
	size_t inputSize = sealed.size - 1 - info.nonceSize;
	SecretBytes plaintext(inputSize - info.tagSize);
	size_t written = 0;
	psa_status_t status = psa_aead_decrypt(imported.Value().Id(), info.algorithm, nonce, info.nonceSize,
	                                       authenticated.data(), authenticated.size(), input, inputSize,
	                                       plaintext.data(), plaintext.size(), &written);
	if (status == PSA_ERROR_INVALID_SIGNATURE)
		return notOpened;
	if (status != PSA_SUCCESS)
		return LibraryError{status, "psa_aead_decrypt"};
	if (written != plaintext.size())
		return LibraryError{PSA_ERROR_CORRUPTION_DETECTED, "psa_aead_decrypt"};
	return std::optional<SecretBytes>(std::move(plaintext));
}

} // namespace smcrypto
