/* Copyright 2026 ETF2L Contributors, Dave
 *
 * Hashing a file, as the worker thread does it: in chunks, stopping at the
 * next chunk once cancelled. Paths are UTF-8 on every platform; symbolic
 * links are followed, also to targets outside the game directory. */
#ifndef SMCRYPTO_CORE_FILE_HASH_H
#define SMCRYPTO_CORE_FILE_HASH_H

#include "hash.h"

#include <atomic>
#include <optional>
#include <string>

namespace smcrypto {

/* How a file job ended; the extension maps it to CryptoError. */
enum class FileError {
	None,
	NotFound,    /* nothing is at the path */
	NotAFile,    /* a directory, a FIFO or another kind of non-regular file */
	Open,        /* the file cannot be opened, e.g. no permission */
	Read,        /* reading failed */
	Cancelled,   /* Crypto.Cancel */
	Internal,    /* the library failed (library tells why) or memory ran out */
	InvalidPath, /* a refused job: its path breaks the path rule; never from HashFile */
};

struct FileHashOutcome {
	FileError error = FileError::None;
	Bytes digest;                         /* empty unless error is None */
	std::optional<LibraryError> library;  /* set for Internal when the library failed */
};

/* The bytes read per chunk. */
constexpr size_t kFileChunkSize = 64 * 1024;

FileHashOutcome HashFile(Hash hash, const std::string &path, const std::atomic<bool> &isCancelled);

} // namespace smcrypto

#endif // SMCRYPTO_CORE_FILE_HASH_H
