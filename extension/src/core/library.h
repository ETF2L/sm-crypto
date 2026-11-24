/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The crypto library behind the core: Mbed TLS, used only through its PSA
 * Crypto API, which later major versions keep. Every call that can fail for
 * reasons other than its input returns a Result: the value, or the library's
 * error with the function that reported it, for a loud native error.
 *
 * Threads: Mbed TLS is built without its threading layer, so only the main
 * thread may use keys, the random generator and initialization. The worker
 * thread only runs unkeyed hash operations (HashStream), which keep their
 * state in the operation itself. */
#ifndef SMCRYPTO_CORE_LIBRARY_H
#define SMCRYPTO_CORE_LIBRARY_H

#include <cstdint>
#include <string>
#include <utility>
#include <variant>

namespace smcrypto {

/* A failure the library reported. */
struct LibraryError {
	int32_t status = 0;           /* the PSA status code */
	const char *function = "";    /* the PSA function that failed */

	/* "psa_aead_encrypt failed: PSA_ERROR_INSUFFICIENT_MEMORY (-141)" */
	std::string Describe() const;
};

/* A value or the library's error. */
template <typename T>
class Result {
public:
	Result(T value) : m_state(std::move(value)) {}
	Result(LibraryError error) : m_state(error) {}

	bool IsOk() const { return std::holds_alternative<T>(m_state); }
	const T &Value() const { return std::get<T>(m_state); }
	T &Value() { return std::get<T>(m_state); }
	const LibraryError &Error() const { return std::get<LibraryError>(m_state); }

private:
	std::variant<T, LibraryError> m_state;
};

/* A Result without a value. */
struct Done {};
using Status = Result<Done>;

/* Starts the library: its key store and its random generator, seeded from
 * the system's entropy. Must succeed before anything else is used. */
Status InitializeLibrary();

/* Frees the library's state; keys and operations must be gone. */
void ShutdownLibrary();

/* "Mbed TLS 3.6.5" */
const char *LibraryVersion();

} // namespace smcrypto

#endif // SMCRYPTO_CORE_LIBRARY_H
