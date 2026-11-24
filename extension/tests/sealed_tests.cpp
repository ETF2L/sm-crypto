/* Copyright 2026 ETF2L Contributors, Dave
 *
 * Sealed messages: known answers from an independent implementation
 * (tools/sealed_vectors.py), round trips, and every change to a message
 * refused. */
#include "check.h"
#include "sealed.h"

#include <algorithm>
#include <stdexcept>
#include <string>

using namespace smcrypto;
using tests::FromHex;
using tests::ToHex;

namespace {

struct Vector {
	Cipher cipher;
	const char *key;
	const char *plaintext;
	const char *aad;
	const char *sealed;
};

/* tools/sealed_vectors.py, with the nonce 64656667...6f. */
const Vector kVectors[] = {
	{Cipher::AES256GCM, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "", "",
	 "016465666768696a6b6c6d6e6f96454fb7ccb36e5063756e0ca308bd22"},
	{Cipher::AES256GCM, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "SMCrypto sealed message", "",
	 "016465666768696a6b6c6d6e6f1b569d14009922f11e113a89b6000edd2fa77579ea0b96c23b069479996e572d5b39bd29b089b6"},
	{Cipher::AES256GCM, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "SMCrypto sealed message",
	 "STEAM_0:1:23",
	 "016465666768696a6b6c6d6e6f1b569d14009922f11e113a89b6000edd2fa77579ea0b96d11d312b9d90593929cbc1f373a9ac9d"},
	{Cipher::ChaCha20Poly1305, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", "", "",
	 "026465666768696a6b6c6d6e6f8d822fb263b8b1e00f8dbef5b894ec4a"},
	{Cipher::ChaCha20Poly1305, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
	 "SMCrypto sealed message", "",
	 "026465666768696a6b6c6d6e6fd7e6bb4dbcd62ce5e6d9833b508f11009c1dede979940154e780b73efaadb62f0f71e634867143"},
	{Cipher::ChaCha20Poly1305, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
	 "SMCrypto sealed message", "STEAM_0:1:23",
	 "026465666768696a6b6c6d6e6fd7e6bb4dbcd62ce5e6d9833b508f11009c1dede9799401b2abcf70bcc98246d66b3850e64aa600"},
	{Cipher::AES128GCM, "000102030405060708090a0b0c0d0e0f", "", "",
	 "036465666768696a6b6c6d6e6f30fa9dc755171a8655acd99854a21933"},
	{Cipher::AES128GCM, "000102030405060708090a0b0c0d0e0f", "SMCrypto sealed message", "",
	 "036465666768696a6b6c6d6e6f492f0dd7a272cc95bb4d3271eaaf4fcc5ded0b8cf3ceb8f7f7d6e106513285586dc46a05f92918"},
	{Cipher::AES128GCM, "000102030405060708090a0b0c0d0e0f", "SMCrypto sealed message", "STEAM_0:1:23",
	 "036465666768696a6b6c6d6e6f492f0dd7a272cc95bb4d3271eaaf4fcc5ded0b8cf3ceb856b4c6662a86805dffc2b69a27bab71d"},
};

const char *const kNonce = "6465666768696a6b6c6d6e6f";

bool Opens(ByteView key, ByteView sealed, ByteView aad)
{
	return MUST(Open(key, sealed, aad)).has_value();
}

} // namespace

TEST(SealingMatchesAnIndependentImplementation)
{
	for (const Vector &vector : kVectors) {
		Bytes key = FromHex(vector.key);
		std::string plaintext = vector.plaintext, aad = vector.aad;
		Bytes sealed = MUST(SealWithNonce(vector.cipher, key, FromHex(kNonce), ByteView(plaintext), ByteView(aad)));
		CHECK_EQ_STR(ToHex(sealed), vector.sealed);
		std::optional<SecretBytes> opened = MUST(Open(key, FromHex(vector.sealed), ByteView(aad)));
		CHECK(opened && std::string(opened->begin(), opened->end()) == plaintext);
	}
}

TEST(SealedMessagesAreAsLongAsTheirFormatSays)
{
	for (Cipher cipher : {Cipher::AES256GCM, Cipher::ChaCha20Poly1305, Cipher::AES128GCM}) {
		CHECK(IsCipherSupported(cipher));
		CHECK(SealedOverhead(cipher) == 29);
		CHECK(SealedNonceSize(cipher) == 12);
		Bytes key(CipherKeySize(cipher), 0x42);
		for (size_t length : {0, 1, 15, 16, 17, 1000}) {
			std::string plaintext(length, 'p');
			CHECK(MUST(Seal(cipher, key, ByteView(plaintext), ByteView())).size() == length + SealedOverhead(cipher));
		}
	}
}

TEST(EachSealUsesAFreshNonce)
{
	Bytes key(32, 0x42);
	std::string plaintext = "same plaintext";
	Bytes first = MUST(Seal(Cipher::ChaCha20Poly1305, key, ByteView(plaintext), ByteView()));
	Bytes second = MUST(Seal(Cipher::ChaCha20Poly1305, key, ByteView(plaintext), ByteView()));
	CHECK(first != second);
	CHECK(!std::equal(first.begin() + 1, first.begin() + 13, second.begin() + 1));
	CHECK(Opens(key, first, ByteView()) && Opens(key, second, ByteView()));
}

TEST(AnyChangedByteKeepsAMessageClosed)
{
	for (const Vector &vector : kVectors) {
		Bytes key = FromHex(vector.key);
		Bytes sealed = FromHex(vector.sealed);
		std::string aad = vector.aad;
		for (size_t i = 0; i < sealed.size(); i++) {
			for (uint8_t flip : {0x01, 0x80}) {
				Bytes changed = sealed;
				changed[i] ^= flip;
				CHECK(!Opens(key, changed, ByteView(aad)));
			}
		}
	}
}

TEST(AMessageOpensOnlyWithItsKeyAndAad)
{
	Bytes key(32, 0x11), otherKey(32, 0x12);
	std::string plaintext = "secret", aad = "STEAM_0:1:23", otherAad = "STEAM_0:1:24";
	Bytes sealed = MUST(Seal(Cipher::AES256GCM, key, ByteView(plaintext), ByteView(aad)));
	CHECK(Opens(key, sealed, ByteView(aad)));
	CHECK(!Opens(otherKey, sealed, ByteView(aad)));
	CHECK(!Opens(key, sealed, ByteView(otherAad)));
	CHECK(!Opens(key, sealed, ByteView()));
	/* A key of another size for the format. */
	Bytes shortKey(16, 0x11);
	CHECK(!Opens(shortKey, sealed, ByteView(aad)));
}

TEST(ShortTruncatedOrUnknownMessagesStayClosed)
{
	Bytes key(32, 0x11);
	std::string plaintext = "secret";
	Bytes sealed = MUST(Seal(Cipher::AES256GCM, key, ByteView(plaintext), ByteView()));
	for (size_t length = 0; length < sealed.size(); length++)
		CHECK(!Opens(key, ByteView(sealed.data(), length), ByteView()));
	Bytes longer = sealed;
	longer.push_back(0);
	CHECK(!Opens(key, longer, ByteView()));
	for (int format : {0x00, 0x04, 0x7f, 0xff}) {
		Bytes unknown = sealed;
		unknown[0] = static_cast<uint8_t>(format);
		CHECK(!Opens(key, unknown, ByteView()));
	}
}

TEST(AChangedFormatByteCannotSwitchTheCipher)
{
	/* AES-256-GCM and ChaCha20-Poly1305 take the same key size. */
	Bytes key(32, 0x33);
	std::string plaintext = "secret";
	Bytes sealed = MUST(Seal(Cipher::AES256GCM, key, ByteView(plaintext), ByteView()));
	sealed[0] = 0x02;
	CHECK(!Opens(key, sealed, ByteView()));
}

/* Whether sealing with key throws for its size, which is a bug of the
 * caller and no library error. */
bool IsKeyRefused(Cipher cipher, ByteView key)
{
	std::string plaintext = "secret";
	try {
		Seal(cipher, key, ByteView(plaintext), ByteView());
	} catch (const std::invalid_argument &) {
		return true;
	}
	return false;
}

TEST(SealingRefusesAKeyOfTheWrongSize)
{
	Bytes shortKey(16, 0x01), longKey(32, 0x01);
	CHECK(IsKeyRefused(Cipher::AES256GCM, shortKey));
	CHECK(IsKeyRefused(Cipher::ChaCha20Poly1305, shortKey));
	CHECK(IsKeyRefused(Cipher::AES128GCM, longKey));
	CHECK(!IsKeyRefused(Cipher::AES256GCM, longKey));
	CHECK(CipherKeySize(Cipher::AES256GCM) == 32 && CipherKeySize(Cipher::AES128GCM) == 16);
}
