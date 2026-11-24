/* Copyright 2026 ETF2L Contributors, Dave
 *
 * One call of a native, as the core sees it: the arguments the plugin
 * passed and the plugin's memory they point into. Every argument is read
 * through it, so every span of plugin memory read or written is checked to
 * lie in one part of the plugin's memory, never across the free gap between
 * its heap and its stack, and no argument the plugin did not pass is read.
 * It knows no SourceMod: the calling plugin is behind CallingPlugin, which
 * the extension implements over SourcePawn and the unit tests with memory
 * of their own.
 *
 * Every reader and writer returns false after reporting a native error;
 * the native then returns at once. */
#ifndef SMCRYPTO_CORE_NATIVE_CALL_H
#define SMCRYPTO_CORE_NATIVE_CALL_H

#include "encoding.h"
#include "hash.h"
#include "library.h"
#include "sealed.h"

#include <cstdint>
#include <optional>

#if defined(__GNUC__)
#define SMCRYPTO_PRINTF(formatIndex, firstIndex) __attribute__((format(printf, formatIndex, firstIndex)))
#else
#define SMCRYPTO_PRINTF(formatIndex, firstIndex)
#endif

namespace smcrypto {

/* A plugin's cell: SourcePawn's cell_t. */
using Cell = int32_t;

/* The plugin that called a native, the seam to the VM. A plugin's memory
 * is data and heap from 0 up to its heap pointer, a free gap, and its stack
 * from its stack pointer to the end. */
class CallingPlugin {
public:
	virtual ~CallingPlugin() = default;

	/* The byte at address, or nullptr when address lies outside the
	 * plugin's memory or in the gap. */
	virtual uint8_t *Resolve(Cell address) = 0;

	/* Where the plugin's stack begins during the call, or nothing when it
	 * is unknown: the native was not called by the plugin's code. */
	virtual std::optional<int64_t> StackPointer() const = 0;

	/* Throws message as the native error of the call. */
	virtual void ReportError(const char *message) = 0;
};

/* A buffer that is enough for size bytes and their NUL; no native error. */
bool FitsWithTerminator(size_t size, Cell maxlength);

/* The buffer size an encoded value of size bytes needs, its NUL included;
 * nothing when it exceeds what a plugin's int can hold. */
std::optional<Cell> EncodedBufferSize(size_t size, Encoding encoding);

class NativeCall {
public:
	static constexpr size_t kMaxErrorLength = 1023;

	/* params as SourcePawn passes them: params[0] is the number of
	 * arguments, params[1] the first. */
	NativeCall(CallingPlugin &plugin, const Cell *params);
	virtual ~NativeCall() = default;
	NativeCall(const NativeCall &) = delete;
	NativeCall &operator=(const NativeCall &) = delete;

	/* Whether the plugin passed at least count arguments. A plugin compiled
	 * against an older smcrypto.inc passes fewer to a native that gained
	 * optional ones. */
	bool HasArguments(Cell count);

	/* Whether the plugin passed argument index (from 1). */
	bool IsPassed(int index) const;

	/* Argument index as the plugin passed it. Throws std::out_of_range when
	 * it was not passed: reading it would read the plugin's stack. */
	Cell Arg(int index) const;

	/* Reports a native error, cut to kMaxErrorLength bytes; always false.
	 * Allocates nothing, so it cannot throw. */
	bool Fail(const char *format, ...) SMCRYPTO_PRINTF(2, 3);

	/* Reports the native error of a library failure; always false. */
	bool FailWith(const LibraryError &error);

	/* A CryptoHash this build of the library has. */
	bool ReadHash(int index, Hash &hash);
	bool ReadEncoding(int index, Encoding &encoding);
	/* A CryptoCipher this build of the library has. */
	bool ReadCipher(int index, Cipher &cipher);

	/* The bytes at argument address, as many as argument length says, which
	 * must be 0 or more. Valid until the plugin runs again. */
	bool ReadBytes(int address, int length, const char *argument, ByteView &bytes);

	/* Data that is usually text: as many bytes as argument length says, or
	 * up to the NUL for -1. */
	bool ReadData(int address, int length, const char *argument, ByteView &bytes);

	/* The text at argument address, up to its NUL. */
	bool ReadText(int address, const char *argument, ByteView &text);

	/* A cryptographic value in an encoding: its text (up to the NUL for a
	 * length of -1, which CryptoEncoding_Raw refuses), decoded. decoded is
	 * empty when the text is not valid in the encoding; that is no native
	 * error. */
	bool ReadEncoded(int address, int length, Encoding encoding, const char *argument,
	                 std::optional<SecretBytes> &decoded);

	/* Writes bytes and a NUL as they are into the buffer at argument
	 * address of argument maxlength bytes; a native error when they do not
	 * fit. written is their length without the NUL. */
	bool WriteBytes(int address, int maxlength, ByteView bytes, Cell &written);

	/* The same with value in encoding. */
	bool WriteValue(int address, int maxlength, ByteView value, Encoding encoding, Cell &written);

	/* Writes as much of the ASCII text as fits and a NUL into the buffer
	 * at argument address of argument maxlength bytes, which must be 1 or
	 * more. written is the length written without the NUL. */
	bool WriteTruncated(int address, int maxlength, const char *argument, const char *text, Cell &written);

private:
	bool IsAddressValid(int64_t address);
	bool ResolveSpan(Cell address, size_t size, const char *argument, uint8_t *&physical);
	bool ReadStringLength(Cell address, const char *argument, size_t &length);
	bool ReadLength(Cell length, bool isTerminatorAllowed, const char *argument);
	bool ReadSpan(Cell address, Cell length, const char *argument, ByteView &bytes);

	CallingPlugin &m_plugin;
	const Cell *m_params;
	std::optional<int64_t> m_stackPointer;
};

} // namespace smcrypto

#endif // SMCRYPTO_CORE_NATIVE_CALL_H
