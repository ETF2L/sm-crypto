/* Copyright 2026 ETF2L Contributors, Dave */
#include "crypto_error.h"

using smcrypto::FileError;

CryptoError CryptoErrorOf(FileError error)
{
	switch (error) {
	case FileError::None: return CryptoError::None;
	case FileError::NotFound: return CryptoError::NotFound;
	case FileError::NotAFile: return CryptoError::NotAFile;
	case FileError::Open: return CryptoError::Open;
	case FileError::Read: return CryptoError::Read;
	case FileError::Cancelled: return CryptoError::Cancelled;
	case FileError::Internal: return CryptoError::Internal;
	case FileError::InvalidPath: return CryptoError::InvalidPath;
	}
	return CryptoError::Internal;
}

const char *CryptoErrorName(CryptoError error)
{
	static const char *const kNames[kCryptoErrorCount] = {
		"CryptoError_None", "CryptoError_NotFound", "CryptoError_NotAFile", "CryptoError_Open",
		"CryptoError_Read", "CryptoError_Cancelled", "CryptoError_Internal", "CryptoError_InvalidPath",
	};
	return kNames[static_cast<int>(error)];
}
