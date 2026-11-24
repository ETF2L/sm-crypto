/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The natives of the CryptoKey methodmap: making and exporting keys, HKDF,
 * HMAC and sealed messages. */
#include "natives_common.h"

#include "keyed.h"
#include "random.h"

#include <algorithm>

using namespace smcrypto;
using namespace natives;

namespace {

bool IsKeySize(size_t size)
{
	return size >= kMinKeySize && size <= kMaxKeySize;
}

cell_t NewKeyHandle(PluginCall &call, SecretBytes bytes)
{
	return call.CreateHandle(g_SMCrypto.keyType, new KeyObject{std::move(bytes)});
}

/* CryptoKey.Generate(int length) */
cell_t CryptoKey_Generate(PluginCall &call)
{
	cell_t length = call.Arg(1);
	if (length < 0 || !IsKeySize(static_cast<size_t>(length)))
		return call.Fail("Invalid key length %d: 1 to %zu bytes", length, kMaxKeySize);
	Result<SecretBytes> bytes = RandomBytes(static_cast<size_t>(length));
	if (!bytes.IsOk())
		return call.FailWith(bytes.Error());
	return NewKeyHandle(call, std::move(bytes.Value()));
}

/* CryptoKey.Import(const char[] text, CryptoEncoding encoding, int textLength) */
cell_t CryptoKey_Import(PluginCall &call)
{
	Encoding encoding;
	std::optional<SecretBytes> decoded;
	if (!call.ReadEncoding(2, encoding) || !call.ReadEncoded(1, 3, encoding, "text", decoded))
		return 0;
	if (!decoded || !IsKeySize(decoded->size()))
		return 0;
	return NewKeyHandle(call, std::move(*decoded));
}

/* CryptoKey.FromString(const char[] secret) */
cell_t CryptoKey_FromString(PluginCall &call)
{
	ByteView secret;
	if (!call.ReadText(1, "secret", secret))
		return 0;
	if (!IsKeySize(secret.size))
		return call.Fail("A secret of %zu bytes is no key: 1 to %zu bytes", secret.size, kMaxKeySize);
	return NewKeyHandle(call, SecretBytes(secret.data, secret.data + secret.size));
}

/* CryptoKey.Length.get */
cell_t CryptoKey_LengthGet(PluginCall &call)
{
	KeyObject *key = call.ReadKey(1);
	return key ? static_cast<cell_t>(key->bytes.size()) : 0;
}

/* CryptoKey.Export(char[] output, int maxlength, CryptoEncoding encoding) */
cell_t CryptoKey_Export(PluginCall &call)
{
	KeyObject *key = call.ReadKey(1);
	Encoding encoding;
	if (!key || !call.ReadEncoding(4, encoding))
		return 0;
	cell_t written = 0;
	call.WriteValue(2, 3, key->bytes, encoding, written);
	return written;
}

/* CryptoKey.Derive(const char[] info, int length, const char[] salt, CryptoHash hash, int infoLength,
 *                  int saltLength) */
cell_t CryptoKey_Derive(PluginCall &call)
{
	KeyObject *key = call.ReadKey(1);
	Hash hash;
	ByteView info, salt;
	if (!key || !call.ReadHash(5, hash) || !call.ReadData(2, 6, "info", info) || !call.ReadData(4, 7, "salt", salt))
		return 0;
	cell_t length = call.Arg(3);
	size_t maxLength = std::min(kMaxKeySize, MaxHkdfLength(hash));
	if (length < 1 || static_cast<size_t>(length) > maxLength)
		return call.Fail("Invalid key length %d: 1 to %zu bytes with %s", length, maxLength, HashName(hash));
	Result<SecretBytes> derived = DeriveHkdf(hash, key->bytes, salt, info, static_cast<size_t>(length));
	if (!derived.IsOk())
		return call.FailWith(derived.Error());
	return NewKeyHandle(call, std::move(derived.Value()));
}

/* CryptoKey.Hmac(CryptoHash hash, const char[] message, char[] output, int maxlength, CryptoEncoding encoding,
 *                int messageLength) */
cell_t CryptoKey_Hmac(PluginCall &call)
{
	KeyObject *key = call.ReadKey(1);
	Hash hash;
	Encoding encoding;
	ByteView message;
	if (!key || !call.ReadHash(2, hash) || !call.ReadEncoding(6, encoding) ||
	    !call.ReadData(3, 7, "message", message))
		return 0;
	Result<Bytes> mac = ComputeHmac(hash, key->bytes, message);
	if (!mac.IsOk())
		return call.FailWith(mac.Error());
	cell_t written = 0;
	call.WriteValue(4, 5, mac.Value(), encoding, written);
	return written;
}

/* CryptoKey.HmacVerify(CryptoHash hash, const char[] message, const char[] mac, CryptoEncoding macEncoding,
 *                      int messageLength, int macLength) */
cell_t CryptoKey_HmacVerify(PluginCall &call)
{
	KeyObject *key = call.ReadKey(1);
	Hash hash;
	Encoding macEncoding;
	ByteView message;
	std::optional<SecretBytes> mac;
	if (!key || !call.ReadHash(2, hash) || !call.ReadEncoding(5, macEncoding) ||
	    !call.ReadData(3, 6, "message", message) || !call.ReadEncoded(4, 7, macEncoding, "mac", mac))
		return 0;
	if (!mac)
		return 0;
	Result<bool> isValid = VerifyHmac(hash, key->bytes, message, *mac);
	if (!isValid.IsOk())
		return call.FailWith(isValid.Error());
	return isValid.Value() ? 1 : 0;
}

/* CryptoKey.Seal(const char[] plaintext, char[] output, int maxlength, CryptoEncoding encoding,
 *                CryptoCipher cipher, const char[] aad, int plaintextLength, int aadLength) */
cell_t CryptoKey_Seal(PluginCall &call)
{
	KeyObject *key = call.ReadKey(1);
	Encoding encoding;
	Cipher cipher;
	ByteView plaintext, aad;
	if (!key || !call.ReadEncoding(5, encoding) || !call.ReadCipher(6, cipher) ||
	    !call.ReadData(2, 8, "plaintext", plaintext) || !call.ReadData(7, 9, "aad", aad))
		return 0;
	if (key->bytes.size() != CipherKeySize(cipher))
		return call.Fail("%s needs a key of %zu bytes, this key has %zu", CipherName(cipher), CipherKeySize(cipher),
		                 key->bytes.size());
	Result<Bytes> sealed = Seal(cipher, key->bytes, plaintext, aad);
	if (!sealed.IsOk())
		return call.FailWith(sealed.Error());
	cell_t written = 0;
	call.WriteValue(3, 4, sealed.Value(), encoding, written);
	return written;
}

/* CryptoKey.Open(const char[] message, char[] output, int maxlength, CryptoEncoding encoding, const char[] aad,
 *                int messageLength, int aadLength) */
cell_t CryptoKey_Open(PluginCall &call)
{
	constexpr cell_t kNotOpened = -1;
	KeyObject *key = call.ReadKey(1);
	Encoding encoding;
	ByteView aad;
	std::optional<SecretBytes> message;
	if (!key || !call.ReadEncoding(5, encoding) || !call.ReadEncoded(2, 7, encoding, "message", message) ||
	    !call.ReadData(6, 8, "aad", aad))
		return 0;
	if (!message)
		return kNotOpened;
	Result<std::optional<SecretBytes>> opened = Open(key->bytes, *message, aad);
	if (!opened.IsOk())
		return call.FailWith(opened.Error());
	if (!opened.Value())
		return kNotOpened;
	cell_t written = 0;
	call.WriteBytes(3, 4, *opened.Value(), written);
	return written;
}

} // namespace

const sp_nativeinfo_t g_KeyNatives[] = {
	{"CryptoKey.Generate", Checked<1, CryptoKey_Generate>},
	{"CryptoKey.Import", Checked<3, CryptoKey_Import>},
	{"CryptoKey.FromString", Checked<1, CryptoKey_FromString>},
	{"CryptoKey.Length.get", Checked<1, CryptoKey_LengthGet>},
	{"CryptoKey.Export", Checked<4, CryptoKey_Export>},
	{"CryptoKey.Derive", Checked<7, CryptoKey_Derive>},
	{"CryptoKey.Hmac", Checked<7, CryptoKey_Hmac>},
	{"CryptoKey.HmacVerify", Checked<7, CryptoKey_HmacVerify>},
	{"CryptoKey.Seal", Checked<9, CryptoKey_Seal>},
	{"CryptoKey.Open", Checked<8, CryptoKey_Open>},
	{nullptr, nullptr},
};
