/* Copyright 2026 ETF2L Contributors, Dave */
#include "file_hash.h"

#include <cerrno>
#include <cstdio>
#include <memory>

#include <sys/stat.h>
#include <sys/types.h>

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace smcrypto {

namespace {

struct FileCloser {
	void operator()(FILE *file) const { fclose(file); }
};
using FileHandle = std::unique_ptr<FILE, FileCloser>;

/* A regular file opened for reading, or why there is none. */
struct OpenedFile {
	FileError error = FileError::None;
	FileHandle file;
};

OpenedFile Refused(FileError error)
{
	OpenedFile opened;
	opened.error = error;
	return opened;
}

/* Why a path could not be looked at or opened, from errno: nothing at the
 * path, or anything else, such as no permission. */
FileError ErrorOfErrno()
{
	return errno == ENOENT || errno == ENOTDIR ? FileError::NotFound : FileError::Open;
}

#ifdef _WIN32

std::wstring Widen(const std::string &utf8)
{
	if (utf8.empty())
		return std::wstring();
	int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()),
	                                 nullptr, 0);
	if (length <= 0)
		return std::wstring();
	std::wstring wide(static_cast<size_t>(length), L'\0');
	MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), &wide[0], length);
	return wide;
}

bool IsRegular(unsigned short mode)
{
	return (mode & _S_IFMT) == _S_IFREG;
}

/* A DOS device name (CON, NUL, COM1, ...) names a device in any directory,
 * with any extension; opening one may act on the device. */
bool IsDeviceName(const std::wstring &path)
{
	static const wchar_t *const kDevices[] = {
		L"CON", L"PRN", L"AUX", L"NUL", L"CONIN$", L"CONOUT$",
		L"COM1", L"COM2", L"COM3", L"COM4", L"COM5", L"COM6", L"COM7", L"COM8", L"COM9",
		L"LPT1", L"LPT2", L"LPT3", L"LPT4", L"LPT5", L"LPT6", L"LPT7", L"LPT8", L"LPT9",
		L"COM\u00b9", L"COM\u00b2", L"COM\u00b3", L"LPT\u00b9", L"LPT\u00b2", L"LPT\u00b3",
	};
	size_t start = 0;
	while (start <= path.size()) {
		size_t end = path.find_first_of(L"\\/", start);
		std::wstring part = path.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start);
		/* The name before the first dot, without trailing spaces. */
		std::wstring base = part.substr(0, part.find(L'.'));
		while (!base.empty() && base.back() == L' ')
			base.pop_back();
		for (const wchar_t *device : kDevices)
			if (_wcsicmp(base.c_str(), device) == 0)
				return true;
		if (end == std::wstring::npos)
			break;
		start = end + 1;
	}
	return false;
}

/* Windows opens no directories as files, so the kind is told first, and
 * checked again on the opened file. */
OpenedFile OpenRegularFile(const std::string &path)
{
	std::wstring wide = Widen(path);
	if (wide.empty())
		return Refused(FileError::Open);
	if (IsDeviceName(wide))
		return Refused(FileError::NotAFile);
	struct _stat64 info;
	if (_wstat64(wide.c_str(), &info) != 0)
		return Refused(ErrorOfErrno());
	if (!IsRegular(info.st_mode))
		return Refused(FileError::NotAFile);
	OpenedFile opened;
	opened.file.reset(_wfopen(wide.c_str(), L"rb"));
	if (!opened.file)
		return Refused(ErrorOfErrno());
	if (_fstat64(_fileno(opened.file.get()), &info) != 0 || !IsRegular(info.st_mode))
		return Refused(FileError::NotAFile);
	return opened;
}

#else

/* The kind is told before opening, so a device or FIFO behind a symbolic
 * link is never opened, and again from the opened descriptor, so the file
 * cannot be swapped in between; O_NONBLOCK keeps a FIFO swapped in from
 * blocking the open until a writer comes. */
OpenedFile OpenRegularFile(const std::string &path)
{
	struct stat named;
	if (stat(path.c_str(), &named) != 0)
		return Refused(ErrorOfErrno());
	if (!S_ISREG(named.st_mode))
		return Refused(FileError::NotAFile);
	int descriptor = open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (descriptor < 0)
		return Refused(ErrorOfErrno());
	struct stat info;
	if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode)) {
		close(descriptor);
		return Refused(FileError::NotAFile);
	}
	int flags = fcntl(descriptor, F_GETFL);
	if (flags == -1 || fcntl(descriptor, F_SETFL, flags & ~O_NONBLOCK) == -1) {
		close(descriptor);
		return Refused(FileError::Open);
	}
	OpenedFile opened;
	opened.file.reset(fdopen(descriptor, "rb"));
	if (!opened.file) {
		close(descriptor);
		return Refused(FileError::Open);
	}
	return opened;
}

#endif

FileHashOutcome Failed(FileError error)
{
	FileHashOutcome outcome;
	outcome.error = error;
	return outcome;
}

FileHashOutcome FailedInLibrary(const LibraryError &library)
{
	FileHashOutcome outcome;
	outcome.error = FileError::Internal;
	outcome.library = library;
	return outcome;
}

} // namespace

FileHashOutcome HashFile(Hash hash, const std::string &path, const std::atomic<bool> &isCancelled)
{
	OpenedFile opened = OpenRegularFile(path);
	if (!opened.file)
		return Failed(opened.error);
	FILE *file = opened.file.get();

	Result<std::unique_ptr<HashStream>> stream = HashStream::Start(hash);
	if (!stream.IsOk())
		return FailedInLibrary(stream.Error());
	Bytes chunk(kFileChunkSize);
	for (;;) {
		if (isCancelled.load())
			return Failed(FileError::Cancelled);
		size_t read = fread(chunk.data(), 1, chunk.size(), file);
		if (read > 0) {
			Status updated = stream.Value()->Update(ByteView(chunk.data(), read));
			if (!updated.IsOk())
				return FailedInLibrary(updated.Error());
		}
		if (read == chunk.size())
			continue;
		if (ferror(file))
			return Failed(FileError::Read);
		break;
	}

	Result<Bytes> digest = stream.Value()->Finish();
	if (!digest.IsOk())
		return FailedInLibrary(digest.Error());
	FileHashOutcome outcome;
	outcome.digest = std::move(digest.Value());
	return outcome;
}

} // namespace smcrypto
