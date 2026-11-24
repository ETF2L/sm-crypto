/* Copyright 2026 ETF2L Contributors, Dave
 *
 * HMAC against RFC 4231 and Python's hmac module, verification, HMAC
 * streams, and HKDF against RFC 5869. */
#include "check.h"
#include "keyed.h"

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

using namespace smcrypto;
using tests::FromHex;
using tests::ToHex;

namespace {

const std::string kFox = "The quick brown fox jumps over the lazy dog";

} // namespace

TEST(HmacMatchesRfc4231)
{
	Bytes key1(20, 0x0b);
	std::string hiThere = "Hi There";
	CHECK_EQ_STR(ToHex(MUST(ComputeHmac(Hash::SHA256, key1, ByteView(hiThere)))),
	             "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
	CHECK_EQ_STR(ToHex(MUST(ComputeHmac(Hash::SHA512, key1, ByteView(hiThere)))),
	             "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4"
	             "be9d914eeb61f1702e696c203a126854");
	CHECK_EQ_STR(ToHex(MUST(ComputeHmac(Hash::SHA256, ByteView(std::string("Jefe")),
	                                    ByteView(std::string("what do ya want for nothing?"))))),
	             "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
	/* A key longer than the block is hashed first. */
	Bytes longKey(131, 0xaa);
	CHECK_EQ_STR(ToHex(MUST(ComputeHmac(Hash::SHA256, longKey,
	                                    ByteView(std::string("Test Using Larger Than Block-Size Key - Hash Key First"))))),
	             "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

TEST(HmacWorksWithSha3AndTheLegacyHashes)
{
	std::string keyText = "key";
	CHECK_EQ_STR(ToHex(MUST(ComputeHmac(Hash::SHA3_256, ByteView(keyText), ByteView(kFox)))),
	             "8c6e0683409427f8931711b10ca92a506eb1fafa48fadd66d76126f47ac2c333");
	CHECK_EQ_STR(ToHex(MUST(ComputeHmac(Hash::SHA1, ByteView(keyText), ByteView(kFox)))),
	             "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
	CHECK_EQ_STR(ToHex(MUST(ComputeHmac(Hash::MD5, ByteView(keyText), ByteView(kFox)))),
	             "80070713463e7749b90c2dc24911e275");
}

TEST(HmacVerificationTakesOnlyTheExactMac)
{
	std::string keyText = "key";
	Bytes mac = MUST(ComputeHmac(Hash::SHA256, ByteView(keyText), ByteView(kFox)));
	CHECK(MUST(VerifyHmac(Hash::SHA256, ByteView(keyText), ByteView(kFox), mac)));

	Bytes changed = mac;
	changed[31] ^= 0x01;
	CHECK(!MUST(VerifyHmac(Hash::SHA256, ByteView(keyText), ByteView(kFox), changed)));
	Bytes truncated(mac.begin(), mac.end() - 1);
	CHECK(!MUST(VerifyHmac(Hash::SHA256, ByteView(keyText), ByteView(kFox), truncated)));
	CHECK(!MUST(VerifyHmac(Hash::SHA256, ByteView(keyText), ByteView(kFox), ByteView())));
	std::string otherMessage = kFox + ".";
	CHECK(!MUST(VerifyHmac(Hash::SHA256, ByteView(keyText), ByteView(otherMessage), mac)));
	std::string otherKey = "kez";
	CHECK(!MUST(VerifyHmac(Hash::SHA256, ByteView(otherKey), ByteView(kFox), mac)));
}

TEST(AnHmacStreamMacsLikeOneShot)
{
	std::string keyText = "stream key";
	for (Hash hash : {Hash::SHA256, Hash::SHA512, Hash::SHA3_384, Hash::SHA1}) {
		auto stream = MUST(MacStream::Start(hash, ByteView(keyText)));
		if (!stream)
			continue;
		CHECK(stream->Update(ByteView(kFox.substr(0, 10))).IsOk());
		CHECK(stream->Update(ByteView()).IsOk());
		CHECK(stream->Update(ByteView(kFox.substr(10))).IsOk());
		CHECK(MUST(stream->Finish()) == MUST(ComputeHmac(hash, ByteView(keyText), ByteView(kFox))));
		CHECK(!stream->Finish().IsOk());
	}
}

TEST(OpenHmacStreamsLeaveRoomForEveryOtherKey)
{
	/* Each stream keeps its key in the library's key store. A key store of
	 * fixed size (32 slots unless MBEDTLS_PSA_KEY_STORE_DYNAMIC) would make
	 * every keyed operation fail once that many digests are open. */
	std::string keyText = "stream key";
	std::vector<std::unique_ptr<MacStream>> streams;
	for (int i = 0; i < 200; i++) {
		Result<std::unique_ptr<MacStream>> stream = MacStream::Start(Hash::SHA256, ByteView(keyText));
		CHECK(stream.IsOk());
		if (!stream.IsOk())
			return;
		streams.push_back(std::move(stream.Value()));
	}
	CHECK(ComputeHmac(Hash::SHA256, ByteView(keyText), ByteView(kFox)).IsOk());
}

TEST(HkdfMatchesRfc5869)
{
	Bytes secret(22, 0x0b);
	Bytes salt = FromHex("000102030405060708090a0b0c");
	Bytes info = FromHex("f0f1f2f3f4f5f6f7f8f9");
	CHECK_EQ_STR(ToHex(MUST(DeriveHkdf(Hash::SHA256, secret, salt, info, 42))),
	             "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
	/* Test case 3: no salt, no info. */
	CHECK_EQ_STR(ToHex(MUST(DeriveHkdf(Hash::SHA256, secret, ByteView(), ByteView(), 42))),
	             "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
}

TEST(HkdfWorksWithSha3AndUpToItsLimit)
{
	std::string secret = "secret", salt = "salt", info = "info";
	CHECK_EQ_STR(ToHex(MUST(DeriveHkdf(Hash::SHA3_256, ByteView(secret), ByteView(salt), ByteView(info), 42))),
	             "52380ffdd0fe5021883e19230ab77444f0e35b804ee938bb72ee66cc421f5c1bf76375194b943f0a21e1");
	CHECK(MaxHkdfLength(Hash::SHA256) == 255 * 32);
	CHECK(MUST(DeriveHkdf(Hash::MD5, ByteView(secret), ByteView(), ByteView(info), MaxHkdfLength(Hash::MD5))).size() ==
	      255 * 16);
	CHECK(!DeriveHkdf(Hash::MD5, ByteView(secret), ByteView(), ByteView(info), MaxHkdfLength(Hash::MD5) + 1).IsOk());
}

TEST(HkdfOutputsDependOnEveryInput)
{
	std::string secret = "secret", salt = "salt", info = "info";
	SecretBytes base = MUST(DeriveHkdf(Hash::SHA256, ByteView(secret), ByteView(salt), ByteView(info), 32));
	std::string other = "other";
	CHECK(base != MUST(DeriveHkdf(Hash::SHA256, ByteView(other), ByteView(salt), ByteView(info), 32)));
	CHECK(base != MUST(DeriveHkdf(Hash::SHA256, ByteView(secret), ByteView(other), ByteView(info), 32)));
	CHECK(base != MUST(DeriveHkdf(Hash::SHA256, ByteView(secret), ByteView(salt), ByteView(other), 32)));
	CHECK(base != MUST(DeriveHkdf(Hash::SHA512, ByteView(secret), ByteView(salt), ByteView(info), 32)));
	/* A shorter output is the longer one's beginning. */
	SecretBytes shorter = MUST(DeriveHkdf(Hash::SHA256, ByteView(secret), ByteView(salt), ByteView(info), 16));
	CHECK(std::equal(shorter.begin(), shorter.end(), base.begin()));
}
