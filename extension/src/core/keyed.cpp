/* Copyright 2026 ETF2L Contributors, Dave */
#include "keyed.h"
#include "psa_key.h"

#include <psa/crypto.h>

namespace smcrypto {

namespace {

Result<ImportedKey> ImportHmacKey(Hash hash, ByteView key, psa_key_usage_t usage)
{
	return ImportedKey::Import(PSA_KEY_TYPE_HMAC, PSA_ALG_HMAC(HashAlgorithm(hash)), usage, key);
}

} // namespace

Result<Bytes> ComputeHmac(Hash hash, ByteView key, ByteView message)
{
	Result<ImportedKey> imported = ImportHmacKey(hash, key, PSA_KEY_USAGE_SIGN_MESSAGE);
	if (!imported.IsOk())
		return imported.Error();
	Bytes mac(HashSize(hash));
	size_t length = 0;
	psa_status_t status = psa_mac_compute(imported.Value().Id(), PSA_ALG_HMAC(HashAlgorithm(hash)), message.data,
	                                      message.size, mac.data(), mac.size(), &length);
	if (status != PSA_SUCCESS)
		return LibraryError{status, "psa_mac_compute"};
	return mac;
}

Result<bool> VerifyHmac(Hash hash, ByteView key, ByteView message, ByteView mac)
{
	Result<ImportedKey> imported = ImportHmacKey(hash, key, PSA_KEY_USAGE_VERIFY_MESSAGE);
	if (!imported.IsOk())
		return imported.Error();
	psa_status_t status = psa_mac_verify(imported.Value().Id(), PSA_ALG_HMAC(HashAlgorithm(hash)), message.data,
	                                     message.size, mac.data, mac.size);
	if (status == PSA_ERROR_INVALID_SIGNATURE)
		return false;
	if (status != PSA_SUCCESS)
		return LibraryError{status, "psa_mac_verify"};
	return true;
}

struct MacStream::Operation {
	ImportedKey key;
	psa_mac_operation_t psa = PSA_MAC_OPERATION_INIT;
	bool isActive = true;

	explicit Operation(ImportedKey imported) : key(std::move(imported)) {}
	/* Aborted before key's destructor destroys the key it uses. */
	~Operation() { psa_mac_abort(&psa); }
};

MacStream::MacStream(Hash hash, std::unique_ptr<Operation> operation) : m_hash(hash), m_operation(std::move(operation))
{
}

MacStream::~MacStream() = default;

Result<std::unique_ptr<MacStream>> MacStream::Start(Hash hash, ByteView key)
{
	Result<ImportedKey> imported = ImportHmacKey(hash, key, PSA_KEY_USAGE_SIGN_MESSAGE);
	if (!imported.IsOk())
		return imported.Error();
	auto operation = std::make_unique<Operation>(std::move(imported.Value()));
	psa_status_t status = psa_mac_sign_setup(&operation->psa, operation->key.Id(), PSA_ALG_HMAC(HashAlgorithm(hash)));
	if (status != PSA_SUCCESS)
		return LibraryError{status, "psa_mac_sign_setup"};
	return std::unique_ptr<MacStream>(new MacStream(hash, std::move(operation)));
}

Status MacStream::Update(ByteView data)
{
	if (!m_operation->isActive)
		return LibraryError{PSA_ERROR_BAD_STATE, "psa_mac_update"};
	psa_status_t status = psa_mac_update(&m_operation->psa, data.data, data.size);
	if (status != PSA_SUCCESS) {
		m_operation->isActive = false;
		return LibraryError{status, "psa_mac_update"};
	}
	return Done{};
}

Result<Bytes> MacStream::Finish()
{
	if (!m_operation->isActive)
		return LibraryError{PSA_ERROR_BAD_STATE, "psa_mac_sign_finish"};
	m_operation->isActive = false;
	Bytes mac(HashSize(m_hash));
	size_t length = 0;
	psa_status_t status = psa_mac_sign_finish(&m_operation->psa, mac.data(), mac.size(), &length);
	if (status != PSA_SUCCESS)
		return LibraryError{status, "psa_mac_sign_finish"};
	return mac;
}

size_t MaxHkdfLength(Hash hash)
{
	return 255 * HashSize(hash);
}

Result<SecretBytes> DeriveHkdf(Hash hash, ByteView secret, ByteView salt, ByteView info, size_t length)
{
	struct Derivation {
		psa_key_derivation_operation_t psa = PSA_KEY_DERIVATION_OPERATION_INIT;
		~Derivation() { psa_key_derivation_abort(&psa); }
	} derivation;

	psa_status_t status = psa_key_derivation_setup(&derivation.psa, PSA_ALG_HKDF(HashAlgorithm(hash)));
	if (status != PSA_SUCCESS)
		return LibraryError{status, "psa_key_derivation_setup"};
	/* HKDF takes the salt first; without one, PSA uses the RFC's default. */
	if (!salt.empty()) {
		status = psa_key_derivation_input_bytes(&derivation.psa, PSA_KEY_DERIVATION_INPUT_SALT, salt.data, salt.size);
		if (status != PSA_SUCCESS)
			return LibraryError{status, "psa_key_derivation_input_bytes"};
	}
	status = psa_key_derivation_input_bytes(&derivation.psa, PSA_KEY_DERIVATION_INPUT_SECRET, secret.data, secret.size);
	if (status != PSA_SUCCESS)
		return LibraryError{status, "psa_key_derivation_input_bytes"};
	status = psa_key_derivation_input_bytes(&derivation.psa, PSA_KEY_DERIVATION_INPUT_INFO, info.data, info.size);
	if (status != PSA_SUCCESS)
		return LibraryError{status, "psa_key_derivation_input_bytes"};

	SecretBytes output(length);
	status = psa_key_derivation_output_bytes(&derivation.psa, output.data(), output.size());
	if (status != PSA_SUCCESS)
		return LibraryError{status, "psa_key_derivation_output_bytes"};
	return output;
}

} // namespace smcrypto
