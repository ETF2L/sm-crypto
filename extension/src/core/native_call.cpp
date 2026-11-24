/* Copyright 2026 ETF2L Contributors, Dave */
#include "native_call.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>

namespace smcrypto {

namespace {

constexpr int64_t kMaxCell = std::numeric_limits<Cell>::max();
constexpr Cell kUpToTerminator = -1;
/* The plugin memory a terminator is searched in per range check. */
constexpr size_t kScanChunk = 4096;

} // namespace

bool FitsWithTerminator(size_t size, Cell maxlength)
{
	return maxlength > 0 && size < static_cast<size_t>(maxlength);
}

std::optional<Cell> EncodedBufferSize(size_t size, Encoding encoding)
{
	uint64_t needed = EncodedLength(size, encoding) + 1;
	if (needed > static_cast<uint64_t>(kMaxCell))
		return std::nullopt;
	return static_cast<Cell>(needed);
}

NativeCall::NativeCall(CallingPlugin &plugin, const Cell *params)
	: m_plugin(plugin), m_params(params), m_stackPointer(plugin.StackPointer())
{
}

bool NativeCall::HasArguments(Cell count)
{
	if (m_params[0] >= count)
		return true;
	return Fail("The native takes %d arguments, the plugin passed %d: it was compiled against another "
	            "smcrypto.inc than this extension's", count, m_params[0]);
}

bool NativeCall::IsPassed(int index) const
{
	return index >= 1 && index <= m_params[0];
}

Cell NativeCall::Arg(int index) const
{
	if (!IsPassed(index))
		throw std::out_of_range("the native read argument " + std::to_string(index) + " of " +
		                        std::to_string(m_params[0]));
	return m_params[index];
}

bool NativeCall::Fail(const char *format, ...)
{
	char message[kMaxErrorLength + 1];
	va_list arguments;
	va_start(arguments, format);
	int length = vsnprintf(message, sizeof(message), format, arguments);
	va_end(arguments);
	m_plugin.ReportError(length < 0 ? format : message);
	return false;
}

bool NativeCall::FailWith(const LibraryError &error)
{
	return Fail("%s: %s", LibraryVersion(), error.Describe().c_str());
}

bool NativeCall::ReadHash(int index, Hash &hash)
{
	Cell value = Arg(index);
	if (value < 0 || value >= kHashCount)
		return Fail("Invalid CryptoHash %d", value);
	hash = static_cast<Hash>(value);
	if (!IsHashSupported(hash))
		return Fail("%s is not supported by this build of %s", HashName(hash), LibraryVersion());
	return true;
}

bool NativeCall::ReadEncoding(int index, Encoding &encoding)
{
	Cell value = Arg(index);
	if (value < 0 || value >= kEncodingCount)
		return Fail("Invalid CryptoEncoding %d", value);
	encoding = static_cast<Encoding>(value);
	return true;
}

bool NativeCall::ReadCipher(int index, Cipher &cipher)
{
	Cell value = Arg(index);
	if (value < 0 || value >= kCipherCount)
		return Fail("Invalid CryptoCipher %d", value);
	cipher = static_cast<Cipher>(value);
	if (!IsCipherSupported(cipher))
		return Fail("%s is not supported by this build of %s", CipherName(cipher), LibraryVersion());
	return true;
}

bool NativeCall::IsAddressValid(int64_t address)
{
	return address >= 0 && address <= kMaxCell && m_plugin.Resolve(static_cast<Cell>(address)) != nullptr;
}

/* The physical address of size bytes at address, after checking that they
 * lie in one part of the plugin's memory. With the first and the last byte
 * valid, the span lies in one part unless it starts below the stack and
 * ends in it, crossing the gap. */
bool NativeCall::ResolveSpan(Cell address, size_t size, const char *argument, uint8_t *&physical)
{
	uint8_t *start = m_plugin.Resolve(address);
	if (!start)
		return Fail("%s: invalid address %x", argument, address);
	if (!m_stackPointer)
		return Fail("%s: the plugin's stack is unknown, so its memory cannot be checked: the native was not called "
		            "by the plugin's code", argument);
	int64_t stack = *m_stackPointer;
	int64_t last = static_cast<int64_t>(address) + static_cast<int64_t>(size) - 1;
	bool isCrossingTheGap = address < stack && last >= stack;
	if (size > 0 && (!IsAddressValid(last) || isCrossingTheGap))
		return Fail("%s: %zu bytes do not fit into the plugin's memory", argument, size);
	physical = start;
	return true;
}

/* The length of the string at address, never reading past the plugin's
 * memory: it is searched in chunks whose last byte was checked, and byte by
 * byte where a chunk would leave the memory. */
bool NativeCall::ReadStringLength(Cell address, const char *argument, size_t &length)
{
	uint8_t *start = nullptr;
	if (!ResolveSpan(address, 0, argument, start))
		return false;
	for (size_t offset = 0;; offset += kScanChunk) {
		int64_t chunkStart = static_cast<int64_t>(address) + static_cast<int64_t>(offset);
		bool isWholeChunkValid = IsAddressValid(chunkStart + static_cast<int64_t>(kScanChunk) - 1);
		for (size_t i = 0; i < kScanChunk; i++) {
			if (!isWholeChunkValid && !IsAddressValid(chunkStart + static_cast<int64_t>(i)))
				return Fail("%s: the string has no terminating NUL", argument);
			if (start[offset + i] == '\0') {
				length = offset + i;
				return true;
			}
		}
	}
}

/* Reads a length argument: 0 or more, or kUpToTerminator when allowed. */
bool NativeCall::ReadLength(Cell length, bool isTerminatorAllowed, const char *argument)
{
	if (length >= 0 || (isTerminatorAllowed && length == kUpToTerminator))
		return true;
	return Fail("%s: invalid length %d", argument, length);
}

/* length bytes at address, or up to the NUL for kUpToTerminator. */
bool NativeCall::ReadSpan(Cell address, Cell length, const char *argument, ByteView &bytes)
{
	if (!ReadLength(length, true, argument))
		return false;
	size_t size = static_cast<size_t>(length);
	if (length == kUpToTerminator && !ReadStringLength(address, argument, size))
		return false;
	uint8_t *physical = nullptr;
	if (!ResolveSpan(address, size, argument, physical))
		return false;
	bytes = ByteView(physical, size);
	return true;
}

bool NativeCall::ReadBytes(int address, int length, const char *argument, ByteView &bytes)
{
	return ReadLength(Arg(length), false, argument) && ReadSpan(Arg(address), Arg(length), argument, bytes);
}

bool NativeCall::ReadData(int address, int length, const char *argument, ByteView &bytes)
{
	return ReadSpan(Arg(address), Arg(length), argument, bytes);
}

bool NativeCall::ReadText(int address, const char *argument, ByteView &text)
{
	return ReadSpan(Arg(address), kUpToTerminator, argument, text);
}

bool NativeCall::ReadEncoded(int address, int length, Encoding encoding, const char *argument,
                             std::optional<SecretBytes> &decoded)
{
	if (encoding == Encoding::Raw && Arg(length) == kUpToTerminator)
		return Fail("%s: CryptoEncoding_Raw needs the value's length", argument);
	ByteView text;
	if (!ReadData(address, length, argument, text))
		return false;
	decoded = Decode(text, encoding);
	return true;
}

bool NativeCall::WriteBytes(int address, int maxlength, ByteView bytes, Cell &written)
{
	Cell size = Arg(maxlength);
	if (bytes.size > static_cast<size_t>(kMaxCell - 1))
		return Fail("output: %zu bytes are more than a plugin can hold", bytes.size);
	if (!FitsWithTerminator(bytes.size, size))
		return Fail("output: a buffer of %d bytes is too small, %zu are needed", size, bytes.size + 1);
	uint8_t *physical = nullptr;
	if (!ResolveSpan(Arg(address), bytes.size + 1, "output", physical))
		return false;
	/* memmove: an output may overlap an input of the same call. */
	if (bytes.size > 0)
		memmove(physical, bytes.data, bytes.size);
	physical[bytes.size] = '\0';
	written = static_cast<Cell>(bytes.size);
	return true;
}

bool NativeCall::WriteValue(int address, int maxlength, ByteView value, Encoding encoding, Cell &written)
{
	SecretBytes encoded = Encode(value, encoding);
	return WriteBytes(address, maxlength, encoded, written);
}

bool NativeCall::WriteTruncated(int address, int maxlength, const char *argument, const char *text, Cell &written)
{
	Cell size = Arg(maxlength);
	if (size < 1)
		return Fail("Invalid buffer size %d", size);
	uint8_t *physical = nullptr;
	if (!ResolveSpan(Arg(address), static_cast<size_t>(size), argument, physical))
		return false;
	size_t length = std::min(strlen(text), static_cast<size_t>(size) - 1);
	memcpy(physical, text, length);
	physical[length] = '\0';
	written = static_cast<Cell>(length);
	return true;
}

} // namespace smcrypto
