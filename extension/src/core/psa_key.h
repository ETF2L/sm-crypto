/* Copyright 2026 ETF2L Contributors, Dave
 *
 * Internal to the core: key material imported into the library's key store
 * for one operation, destroyed again when the ImportedKey goes away. Keys
 * live as plain bytes in the core and only enter the key store while an
 * operation needs them, so no key store state outlives an operation. */
#ifndef SMCRYPTO_CORE_PSA_KEY_H
#define SMCRYPTO_CORE_PSA_KEY_H

#include "bytes.h"
#include "library.h"

#include <psa/crypto.h>

namespace smcrypto {

class ImportedKey {
public:
	static Result<ImportedKey> Import(psa_key_type_t type, psa_algorithm_t algorithm, psa_key_usage_t usage,
	                                  ByteView material)
	{
		psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
		psa_set_key_type(&attributes, type);
		psa_set_key_algorithm(&attributes, algorithm);
		psa_set_key_usage_flags(&attributes, usage);
		psa_set_key_bits(&attributes, PSA_BYTES_TO_BITS(material.size));
		psa_key_id_t id = PSA_KEY_ID_NULL;
		psa_status_t status = psa_import_key(&attributes, material.data, material.size, &id);
		psa_reset_key_attributes(&attributes);
		if (status != PSA_SUCCESS)
			return LibraryError{status, "psa_import_key"};
		return ImportedKey(id);
	}

	ImportedKey(ImportedKey &&other) noexcept : m_id(other.m_id) { other.m_id = PSA_KEY_ID_NULL; }
	ImportedKey &operator=(ImportedKey &&other) noexcept
	{
		std::swap(m_id, other.m_id);
		return *this;
	}
	ImportedKey(const ImportedKey &) = delete;
	ImportedKey &operator=(const ImportedKey &) = delete;

	~ImportedKey()
	{
		if (m_id != PSA_KEY_ID_NULL)
			psa_destroy_key(m_id);
	}

	psa_key_id_t Id() const { return m_id; }

private:
	explicit ImportedKey(psa_key_id_t id) : m_id(id) {}

	psa_key_id_t m_id = PSA_KEY_ID_NULL;
};

} // namespace smcrypto

#endif // SMCRYPTO_CORE_PSA_KEY_H
