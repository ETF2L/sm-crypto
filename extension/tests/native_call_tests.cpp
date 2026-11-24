/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The native call over a fake plugin: spans inside one part of the
 * plugin's memory only, strings up to their NUL, lengths, arguments the
 * plugin did not pass, and outputs that must fit with their NUL. */
#include "check.h"
#include "native_call.h"

#include <cstring>
#include <stdexcept>
#include <vector>

using namespace smcrypto;

namespace {

/* A plugin's memory: data and heap below kHeap, the gap, and the stack
 * from kStack to kMemorySize. */
constexpr Cell kHeap = 8192;
constexpr Cell kStack = 12288;
constexpr Cell kMemorySize = 16384;

class FakePlugin : public CallingPlugin {
public:
	explicit FakePlugin(bool isStackKnown = true) : m_memory(kMemorySize, 'x'), m_isStackKnown(isStackKnown) {}

	uint8_t *Resolve(Cell address) override
	{
		if (address < 0 || address >= kMemorySize || (address >= kHeap && address < kStack))
			return nullptr;
		return m_memory.data() + address;
	}

	std::optional<int64_t> StackPointer() const override
	{
		return m_isStackKnown ? std::optional<int64_t>(kStack) : std::nullopt;
	}

	void ReportError(const char *message) override { errors.push_back(message); }

	void Put(Cell address, const char *text) { memcpy(m_memory.data() + address, text, strlen(text) + 1); }
	std::string At(Cell address) const { return reinterpret_cast<const char *>(m_memory.data() + address); }

	std::vector<std::string> errors;

private:
	std::vector<uint8_t> m_memory;
	bool m_isStackKnown;
};

/* A call with arguments, params[0] their number. */
std::vector<Cell> Params(std::vector<Cell> arguments)
{
	arguments.insert(arguments.begin(), static_cast<Cell>(arguments.size()));
	return arguments;
}

bool HasOneError(const FakePlugin &plugin, const char *part)
{
	return plugin.errors.size() == 1 && plugin.errors[0].find(part) != std::string::npos;
}

} // namespace

TEST(ASpanStaysInsideOnePartOfThePluginsMemory)
{
	Cell gap = kStack - kHeap;
	struct Span {
		Cell address;
		Cell length;
		bool isValid;
	};
	const Span spans[] = {
		{0, kHeap, true},                    /* data and heap */
		{kStack, kMemorySize - kStack, true}, /* the stack */
		{kHeap - 4, 0, true},                /* nothing at a valid address */
		{kHeap - 4, 8, false},               /* into the gap */
		{kHeap - 4, gap + 8, false},         /* across the gap into the stack */
		{kMemorySize - 4, 8, false},         /* past the end */
		{kHeap, 0, false},                   /* in the gap */
		{-1, 0, false},
	};
	for (const Span &span : spans) {
		FakePlugin plugin;
		std::vector<Cell> params = Params({span.address, span.length});
		NativeCall call(plugin, params.data());
		ByteView bytes;
		CHECK(call.ReadBytes(1, 2, "data", bytes) == span.isValid);
		CHECK(plugin.errors.size() == (span.isValid ? 0u : 1u));
		CHECK(!span.isValid || bytes.size == static_cast<size_t>(span.length));
	}
}

TEST(AnUnknownStackRefusesEveryAddress)
{
	FakePlugin plugin(false);
	std::vector<Cell> params = Params({0, 4});
	NativeCall call(plugin, params.data());
	ByteView bytes;
	CHECK(!call.ReadBytes(1, 2, "data", bytes));
	CHECK(HasOneError(plugin, "data: the plugin's stack is unknown"));
}

TEST(TextEndsAtItsNulInsideThePluginsMemory)
{
	FakePlugin plugin;
	plugin.Put(16, "hello");
	plugin.Put(kStack + 16, "on the stack");
	/* Longer than one chunk of the search. */
	std::string longText(5000, 'a');
	plugin.Put(1024, longText.c_str());
	std::vector<Cell> params = Params({16, kStack + 16, 1024, kHeap - 8, kMemorySize - 8});
	NativeCall call(plugin, params.data());
	ByteView text;
	CHECK(call.ReadText(1, "text", text) && text.size == 5);
	CHECK(call.ReadText(2, "text", text) && text.size == 12);
	CHECK(call.ReadText(3, "text", text) && text.size == longText.size());
	CHECK(plugin.errors.empty());
	/* The rest of the memory holds no NUL: neither runs into the gap or
	 * past the end. */
	CHECK(!call.ReadText(4, "text", text));
	CHECK(!call.ReadText(5, "text", text));
	CHECK(plugin.errors.size() == 2);
	for (const std::string &error : plugin.errors)
		CHECK(error == "text: the string has no terminating NUL");
}

TEST(LengthsAreZeroOrMoreOrUpToTheNulForData)
{
	FakePlugin plugin;
	plugin.Put(16, "abc");
	std::vector<Cell> params = Params({16, -1, -2});
	NativeCall call(plugin, params.data());
	ByteView bytes;
	CHECK(call.ReadData(1, 2, "data", bytes) && bytes.size == 3);
	CHECK(!call.ReadBytes(1, 2, "a", bytes));
	CHECK(!call.ReadData(1, 3, "data", bytes));
	CHECK(plugin.errors.size() == 2);
	CHECK(plugin.errors.size() == 2 && plugin.errors[0] == "a: invalid length -1");
	CHECK(plugin.errors.size() == 2 && plugin.errors[1] == "data: invalid length -2");
}

TEST(EncodedValuesDecodeOrAreEmpty)
{
	FakePlugin plugin;
	plugin.Put(16, "00ff");
	plugin.Put(32, "0g");
	std::vector<Cell> params = Params({16, 32, -1});
	NativeCall call(plugin, params.data());
	std::optional<SecretBytes> decoded;
	CHECK(call.ReadEncoded(1, 3, Encoding::Hex, "mac", decoded) && decoded && tests::ToHex(*decoded) == "00ff");
	CHECK(call.ReadEncoded(2, 3, Encoding::Hex, "mac", decoded) && !decoded);
	CHECK(plugin.errors.empty());
	CHECK(!call.ReadEncoded(1, 3, Encoding::Raw, "mac", decoded));
	CHECK(HasOneError(plugin, "mac: CryptoEncoding_Raw needs the value's length"));
}

TEST(ArgumentsThePluginDidNotPassAreNeverRead)
{
	FakePlugin plugin;
	std::vector<Cell> params = Params({7, 8});
	NativeCall call(plugin, params.data());
	CHECK(call.HasArguments(2));
	CHECK(call.Arg(2) == 8);
	CHECK(call.IsPassed(2) && !call.IsPassed(3) && !call.IsPassed(0));
	bool isThrown = false;
	try {
		call.Arg(3);
	} catch (const std::out_of_range &) {
		isThrown = true;
	}
	CHECK(isThrown);
	CHECK(plugin.errors.empty());
	CHECK(!call.HasArguments(3));
	CHECK(HasOneError(plugin, "The native takes 3 arguments, the plugin passed 2"));
}

TEST(EnumArgumentsMustBeValuesOfTheInclude)
{
	FakePlugin plugin;
	std::vector<Cell> params = Params({kHashCount, kEncodingCount, kCipherCount, -1});
	NativeCall call(plugin, params.data());
	Hash hash;
	Encoding encoding;
	Cipher cipher;
	CHECK(!call.ReadHash(1, hash));
	CHECK(!call.ReadEncoding(2, encoding));
	CHECK(!call.ReadCipher(3, cipher));
	CHECK(!call.ReadHash(4, hash));
	CHECK(plugin.errors.size() == 4);
}

TEST(OutputsMustFitWithTheirNul)
{
	FakePlugin plugin;
	std::vector<Cell> params = Params({16, 3, 4, kHeap - 2, kMemorySize - 2});
	NativeCall call(plugin, params.data());
	const std::string value = "abc";
	Cell written = 0;
	CHECK(!call.WriteBytes(1, 2, value, written));
	CHECK(HasOneError(plugin, "output: a buffer of 3 bytes is too small, 4 are needed"));
	CHECK(call.WriteBytes(1, 3, value, written) && written == 3);
	CHECK(plugin.At(16) == "abc");
	/* A buffer that says it is bigger than the memory it is in. */
	CHECK(!call.WriteBytes(4, 3, value, written));
	CHECK(!call.WriteBytes(5, 3, value, written));
	CHECK(plugin.errors.size() == 3);
	CHECK(call.WriteValue(1, 3, ByteView(reinterpret_cast<const uint8_t *>("\x01"), 1), Encoding::Hex, written));
	CHECK(written == 2 && plugin.At(16) == "01");
}

TEST(TruncatedTextFillsTheBuffer)
{
	FakePlugin plugin;
	std::vector<Cell> params = Params({16, 4, 64, 0, kHeap - 2, kMemorySize - 2});
	NativeCall call(plugin, params.data());
	Cell written = 0;
	CHECK(call.WriteTruncated(1, 2, "buffer", "CryptoError_None", written) && written == 3);
	CHECK(plugin.At(16) == "Cry");
	CHECK(call.WriteTruncated(1, 3, "buffer", "CryptoError_None", written) && written == 16);
	CHECK(plugin.At(16) == "CryptoError_None");
	CHECK(!call.WriteTruncated(1, 4, "buffer", "x", written));
	CHECK(HasOneError(plugin, "Invalid buffer size 0"));
	/* A buffer that says it runs into the gap or past the end, even for a
	 * text that would fit. */
	CHECK(!call.WriteTruncated(5, 2, "buffer", "x", written));
	CHECK(!call.WriteTruncated(6, 2, "buffer", "x", written));
	CHECK(plugin.errors.size() == 3);
	for (size_t i = 1; i < plugin.errors.size(); i++)
		CHECK(plugin.errors[i] == "buffer: 4 bytes do not fit into the plugin's memory");
}
