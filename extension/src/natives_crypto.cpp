/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The natives of the Crypto methodmap: hashing, file jobs, encodings,
 * randomness, comparison and what this build supports. */
#include "natives_common.h"

#include "random.h"

using namespace smcrypto;
using namespace natives;

namespace {

/* What Crypto.Random hands out per call. */
constexpr cell_t kMaxRandomBytes = 65536;

/* Crypto.HashSize(CryptoHash hash) */
cell_t Crypto_HashSize(PluginCall &call)
{
	Hash hash;
	if (!call.ReadHash(1, hash))
		return 0;
	return static_cast<cell_t>(HashSize(hash));
}

/* Crypto.IsHashSupported(CryptoHash hash) */
cell_t Crypto_IsHashSupported(PluginCall &call)
{
	cell_t value = call.Arg(1);
	return value >= 0 && value < kHashCount && IsHashSupported(static_cast<Hash>(value)) ? 1 : 0;
}

/* Crypto.IsCipherSupported(CryptoCipher cipher) */
cell_t Crypto_IsCipherSupported(PluginCall &call)
{
	cell_t value = call.Arg(1);
	return value >= 0 && value < kCipherCount && IsCipherSupported(static_cast<Cipher>(value)) ? 1 : 0;
}

/* Crypto.Hash(CryptoHash hash, const char[] data, char[] output, int maxlength, CryptoEncoding encoding,
 *             int dataLength) */
cell_t Crypto_Hash(PluginCall &call)
{
	Hash hash;
	Encoding encoding;
	ByteView data;
	if (!call.ReadHash(1, hash) || !call.ReadEncoding(5, encoding) || !call.ReadData(2, 6, "data", data))
		return 0;
	Result<Bytes> digest = ComputeHash(hash, data);
	if (!digest.IsOk())
		return call.FailWith(digest.Error());
	cell_t written = 0;
	call.WriteValue(3, 4, digest.Value(), encoding, written);
	return written;
}

/* Crypto.HashFile(CryptoHash hash, const char[] path, CryptoHashFileCallback callback, any data,
 *                 CryptoEncoding encoding) */
cell_t Crypto_HashFile(PluginCall &call)
{
	Hash hash;
	FileJobTicket ticket;
	std::string resolved;
	bool isPathAllowed = false;
	if (!call.ReadHash(1, hash) || !call.ReadGamePath(2, ticket.path, resolved, isPathAllowed) ||
	    !call.ReadCallback(3, ticket.callback) || !call.ReadEncoding(5, ticket.encoding))
		return 0;
	ticket.data = call.Arg(4);
	if (!isPathAllowed)
		return g_SMCrypto.Jobs().Refuse(call.Owner(), std::move(ticket));
	return g_SMCrypto.Jobs().Queue(call.Owner(), std::move(ticket), hash, std::move(resolved));
}

/* Crypto.Cancel(int job) */
cell_t Crypto_Cancel(PluginCall &call)
{
	return g_SMCrypto.Jobs().Cancel(call.Owner(), call.Arg(1)) ? 1 : 0;
}

/* Crypto.EncodedSize(int length, CryptoEncoding encoding) */
cell_t Crypto_EncodedSize(PluginCall &call)
{
	Encoding encoding;
	if (!call.ReadEncoding(2, encoding))
		return 0;
	cell_t length = call.Arg(1);
	if (length < 0)
		return call.Fail("Invalid length %d", length);
	std::optional<cell_t> size = EncodedBufferSize(static_cast<size_t>(length), encoding);
	if (!size)
		return call.Fail("%d bytes encoded need more than 2^31 - 1 bytes", length);
	return *size;
}

/* Crypto.Encode(const char[] data, char[] output, int maxlength, CryptoEncoding encoding, int dataLength) */
cell_t Crypto_Encode(PluginCall &call)
{
	Encoding encoding;
	ByteView data;
	if (!call.ReadEncoding(4, encoding) || !call.ReadData(1, 5, "data", data))
		return 0;
	cell_t written = 0;
	call.WriteValue(2, 3, data, encoding, written);
	return written;
}

/* Crypto.Decode(const char[] text, char[] output, int maxlength, CryptoEncoding encoding, int textLength) */
cell_t Crypto_Decode(PluginCall &call)
{
	constexpr cell_t kNotDecoded = -1;
	Encoding encoding;
	std::optional<SecretBytes> decoded;
	if (!call.ReadEncoding(4, encoding) || !call.ReadEncoded(1, 5, encoding, "text", decoded))
		return 0;
	cell_t maxlength = call.Arg(3);
	if (maxlength < 1)
		return call.Fail("Invalid buffer size %d", maxlength);
	/* Too long a value is no plugin bug: text may come from anyone. */
	if (!decoded || !FitsWithTerminator(decoded->size(), maxlength))
		return kNotDecoded;
	cell_t written = 0;
	call.WriteBytes(2, 3, *decoded, written);
	return written;
}

/* Crypto.Random(char[] output, int maxlength, int bytes, CryptoEncoding encoding) */
cell_t Crypto_Random(PluginCall &call)
{
	Encoding encoding;
	if (!call.ReadEncoding(4, encoding))
		return 0;
	cell_t count = call.Arg(3);
	if (count < 1 || count > kMaxRandomBytes)
		return call.Fail("Invalid number of random bytes %d: 1 to %d", count, kMaxRandomBytes);
	Result<SecretBytes> random = RandomBytes(static_cast<size_t>(count));
	if (!random.IsOk())
		return call.FailWith(random.Error());
	cell_t written = 0;
	call.WriteValue(1, 2, random.Value(), encoding, written);
	return written;
}

/* Crypto.RandomInt(int min, int max) */
cell_t Crypto_RandomInt(PluginCall &call)
{
	cell_t min = call.Arg(1);
	cell_t max = call.Arg(2);
	if (min > max)
		return call.Fail("min %d is greater than max %d", min, max);
	Result<int32_t> number = RandomInt(min, max);
	if (!number.IsOk())
		return call.FailWith(number.Error());
	return number.Value();
}

/* Crypto.Equal(const char[] a, const char[] b, int length) */
cell_t Crypto_Equal(PluginCall &call)
{
	ByteView a, b;
	if (!call.ReadBytes(1, 3, "a", a) || !call.ReadBytes(2, 3, "b", b))
		return 0;
	return ConstantTimeEqual(a, b) ? 1 : 0;
}

/* Crypto.SealedSize(int plaintextLength, CryptoEncoding encoding, CryptoCipher cipher) */
cell_t Crypto_SealedSize(PluginCall &call)
{
	Encoding encoding;
	Cipher cipher;
	if (!call.ReadEncoding(2, encoding) || !call.ReadCipher(3, cipher))
		return 0;
	cell_t length = call.Arg(1);
	if (length < 0)
		return call.Fail("Invalid plaintext length %d", length);
	std::optional<cell_t> size = EncodedBufferSize(static_cast<size_t>(length) + SealedOverhead(cipher), encoding);
	if (!size)
		return call.Fail("A sealed message of %d bytes needs more than 2^31 - 1 bytes", length);
	return *size;
}

/* Crypto.ErrorString(CryptoError error, char[] buffer, int maxlength) */
cell_t Crypto_ErrorString(PluginCall &call)
{
	cell_t error = call.Arg(1);
	if (error < 0 || error >= kCryptoErrorCount)
		return call.Fail("Invalid CryptoError %d", error);
	cell_t written = 0;
	call.WriteTruncated(2, 3, "buffer", CryptoErrorName(static_cast<CryptoError>(error)), written);
	return written;
}

} // namespace

const sp_nativeinfo_t g_CryptoNatives[] = {
	{"Crypto.HashSize", Checked<1, Crypto_HashSize>},
	{"Crypto.IsHashSupported", Checked<1, Crypto_IsHashSupported>},
	{"Crypto.IsCipherSupported", Checked<1, Crypto_IsCipherSupported>},
	{"Crypto.Hash", Checked<6, Crypto_Hash>},
	{"Crypto.HashFile", Checked<5, Crypto_HashFile>},
	{"Crypto.Cancel", Checked<1, Crypto_Cancel>},
	{"Crypto.EncodedSize", Checked<2, Crypto_EncodedSize>},
	{"Crypto.Encode", Checked<5, Crypto_Encode>},
	{"Crypto.Decode", Checked<5, Crypto_Decode>},
	{"Crypto.Random", Checked<4, Crypto_Random>},
	{"Crypto.RandomInt", Checked<2, Crypto_RandomInt>},
	{"Crypto.Equal", Checked<3, Crypto_Equal>},
	{"Crypto.SealedSize", Checked<3, Crypto_SealedSize>},
	{"Crypto.ErrorString", Checked<3, Crypto_ErrorString>},
	{nullptr, nullptr},
};
