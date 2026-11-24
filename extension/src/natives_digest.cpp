/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The natives of the CryptoDigest methodmap. */
#include "natives_common.h"

using namespace smcrypto;
using namespace natives;

namespace {

/* The digest of the handle in argument index, or nullptr after a native
 * error when it is invalid or finished. */
Digest *ReadOpenDigest(PluginCall &call, int index)
{
	DigestObject *object = call.ReadDigest(index);
	if (!object)
		return nullptr;
	if (object->digest->IsFinished()) {
		call.Fail("The CryptoDigest is finished: Final or Verify ended it, or an Update failed");
		return nullptr;
	}
	return object->digest.get();
}

cell_t NewDigestHandle(PluginCall &call, Result<std::unique_ptr<Digest>> started)
{
	if (!started.IsOk())
		return call.FailWith(started.Error());
	return call.CreateHandle(g_SMCrypto.digestType, new DigestObject{std::move(started.Value())});
}

/* CryptoDigest(CryptoHash hash) */
cell_t CryptoDigest_New(PluginCall &call)
{
	Hash hash;
	if (!call.ReadHash(1, hash))
		return 0;
	return NewDigestHandle(call, Digest::StartHash(hash));
}

/* CryptoDigest.Hmac(CryptoHash hash, CryptoKey key) */
cell_t CryptoDigest_Hmac(PluginCall &call)
{
	Hash hash;
	if (!call.ReadHash(1, hash))
		return 0;
	KeyObject *key = call.ReadKey(2);
	if (!key)
		return 0;
	return NewDigestHandle(call, Digest::StartHmac(hash, key->bytes));
}

/* CryptoDigest.Hash.get */
cell_t CryptoDigest_HashGet(PluginCall &call)
{
	DigestObject *object = call.ReadDigest(1);
	return object ? static_cast<cell_t>(object->digest->GetHash()) : 0;
}

/* CryptoDigest.IsFinished.get */
cell_t CryptoDigest_IsFinishedGet(PluginCall &call)
{
	DigestObject *object = call.ReadDigest(1);
	return object && object->digest->IsFinished() ? 1 : 0;
}

/* CryptoDigest.Update(const char[] data, int dataLength) */
cell_t CryptoDigest_Update(PluginCall &call)
{
	Digest *digest = ReadOpenDigest(call, 1);
	ByteView data;
	if (!digest || !call.ReadData(2, 3, "data", data))
		return 0;
	Status updated = digest->Update(data);
	if (!updated.IsOk())
		call.FailWith(updated.Error());
	return 0;
}

/* CryptoDigest.Final(char[] output, int maxlength, CryptoEncoding encoding) */
cell_t CryptoDigest_Final(PluginCall &call)
{
	Digest *digest = ReadOpenDigest(call, 1);
	Encoding encoding;
	if (!digest || !call.ReadEncoding(4, encoding))
		return 0;
	/* Checked before Finish(), so a buffer too small does not use up the
	 * digest. */
	cell_t maxlength = call.Arg(3);
	std::optional<cell_t> needed = EncodedBufferSize(HashSize(digest->GetHash()), encoding);
	if (maxlength < *needed)
		return call.Fail("output: a buffer of %d bytes is too small, %d are needed", maxlength, *needed);
	Result<Bytes> value = digest->Finish();
	if (!value.IsOk())
		return call.FailWith(value.Error());
	cell_t written = 0;
	call.WriteValue(2, 3, value.Value(), encoding, written);
	return written;
}

/* CryptoDigest.Verify(const char[] expected, CryptoEncoding encoding, int expectedLength) */
cell_t CryptoDigest_Verify(PluginCall &call)
{
	Digest *digest = ReadOpenDigest(call, 1);
	Encoding encoding;
	std::optional<SecretBytes> expected;
	if (!digest || !call.ReadEncoding(3, encoding) || !call.ReadEncoded(2, 4, encoding, "expected", expected))
		return 0;
	Result<Bytes> value = digest->Finish();
	if (!value.IsOk())
		return call.FailWith(value.Error());
	return expected && ConstantTimeEqual(value.Value(), *expected) ? 1 : 0;
}

} // namespace

const sp_nativeinfo_t g_DigestNatives[] = {
	{"CryptoDigest.CryptoDigest", Checked<1, CryptoDigest_New>},
	{"CryptoDigest.Hmac", Checked<2, CryptoDigest_Hmac>},
	{"CryptoDigest.Hash.get", Checked<1, CryptoDigest_HashGet>},
	{"CryptoDigest.IsFinished.get", Checked<1, CryptoDigest_IsFinishedGet>},
	{"CryptoDigest.Update", Checked<3, CryptoDigest_Update>},
	{"CryptoDigest.Final", Checked<4, CryptoDigest_Final>},
	{"CryptoDigest.Verify", Checked<4, CryptoDigest_Verify>},
	{nullptr, nullptr},
};
