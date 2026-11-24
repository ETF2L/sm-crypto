/* Copyright 2026 ETF2L Contributors, Dave
 *
 * Hex, base64 and base64url: the RFC 4648 vectors both ways, and every
 * text that is not exactly one value's refused. */
#include "check.h"
#include "encoding.h"

#include <cstring>
#include <string>

using namespace smcrypto;

namespace {

std::string EncodeText(const std::string &bytes, Encoding encoding)
{
	SecretBytes text = Encode(ByteView(bytes), encoding);
	return std::string(text.begin(), text.end());
}

bool DecodesTo(const std::string &text, Encoding encoding, const std::string &expected)
{
	std::optional<SecretBytes> bytes = Decode(ByteView(text), encoding);
	return bytes && std::string(bytes->begin(), bytes->end()) == expected;
}

bool IsRefused(const std::string &text, Encoding encoding)
{
	return !Decode(ByteView(text), encoding);
}

struct Vector {
	const char *bytes;
	const char *base64;
	const char *base64url;
	const char *hex;
};

/* RFC 4648, section 10. */
const Vector kVectors[] = {
	{"", "", "", ""},
	{"f", "Zg==", "Zg", "66"},
	{"fo", "Zm8=", "Zm8", "666f"},
	{"foo", "Zm9v", "Zm9v", "666f6f"},
	{"foob", "Zm9vYg==", "Zm9vYg", "666f6f62"},
	{"fooba", "Zm9vYmE=", "Zm9vYmE", "666f6f6261"},
	{"foobar", "Zm9vYmFy", "Zm9vYmFy", "666f6f626172"},
};

} // namespace

TEST(EncodingsMatchRfc4648BothWays)
{
	for (const Vector &vector : kVectors) {
		CHECK_EQ_STR(EncodeText(vector.bytes, Encoding::Base64), vector.base64);
		CHECK_EQ_STR(EncodeText(vector.bytes, Encoding::Base64Url), vector.base64url);
		CHECK_EQ_STR(EncodeText(vector.bytes, Encoding::Hex), vector.hex);
		CHECK(DecodesTo(vector.base64, Encoding::Base64, vector.bytes));
		CHECK(DecodesTo(vector.base64url, Encoding::Base64Url, vector.bytes));
		CHECK(DecodesTo(vector.hex, Encoding::Hex, vector.bytes));
		CHECK(EncodedLength(strlen(vector.bytes), Encoding::Base64) == strlen(vector.base64));
		CHECK(EncodedLength(strlen(vector.bytes), Encoding::Base64Url) == strlen(vector.base64url));
		CHECK(EncodedLength(strlen(vector.bytes), Encoding::Hex) == strlen(vector.hex));
	}
}

TEST(EveryByteSurvivesEveryEncoding)
{
	std::string all;
	for (int value = 0; value < 256; value++)
		all += static_cast<char>(value);
	for (Encoding encoding : {Encoding::Hex, Encoding::Base64, Encoding::Base64Url, Encoding::Raw}) {
		for (size_t length = 0; length <= all.size(); length++) {
			std::string bytes = all.substr(all.size() - length);
			std::string text = EncodeText(bytes, encoding);
			CHECK(text.size() == EncodedLength(length, encoding));
			CHECK(DecodesTo(text, encoding, bytes));
		}
	}
}

TEST(TheTwoBase64AlphabetsDiffer)
{
	std::string bytes("\xfb\xff\xbf", 3);
	CHECK_EQ_STR(EncodeText(bytes, Encoding::Base64), "+/+/");
	CHECK_EQ_STR(EncodeText(bytes, Encoding::Base64Url), "-_-_");
	CHECK(IsRefused("-_-_", Encoding::Base64));
	CHECK(IsRefused("+/+/", Encoding::Base64Url));
}

TEST(HexDecodingTakesEitherCaseAndRefusesTheRest)
{
	CHECK(DecodesTo("DEADbeef", Encoding::Hex, "\xde\xad\xbe\xef"));
	CHECK(IsRefused("abc", Encoding::Hex));
	CHECK(IsRefused("0g", Encoding::Hex));
	CHECK(IsRefused("0 ", Encoding::Hex));
	CHECK(IsRefused("0x00", Encoding::Hex));
}

TEST(Base64RefusesNonCanonicalText)
{
	/* wrong length or padding */
	CHECK(IsRefused("Zg", Encoding::Base64));
	CHECK(IsRefused("Zg=", Encoding::Base64));
	CHECK(IsRefused("Zg===", Encoding::Base64));
	CHECK(IsRefused("Z===", Encoding::Base64));
	CHECK(IsRefused("====", Encoding::Base64));
	CHECK(IsRefused("Zm9v=", Encoding::Base64));
	/* padding inside */
	CHECK(IsRefused("Zg==Zg==", Encoding::Base64));
	CHECK(IsRefused("Z=g=", Encoding::Base64));
	/* bits beyond the value: "Zh==" also reads as "f" */
	CHECK(IsRefused("Zh==", Encoding::Base64));
	CHECK(IsRefused("Zm9=", Encoding::Base64));
	/* characters outside the alphabet, whitespace included */
	CHECK(IsRefused("Zm9v\n", Encoding::Base64));
	CHECK(IsRefused("Zm 9v", Encoding::Base64));
	CHECK(IsRefused("Zm9v!A==", Encoding::Base64));
	CHECK(IsRefused(std::string("Zm\0v", 4), Encoding::Base64));
}

TEST(Base64UrlRefusesPaddingAndNonCanonicalText)
{
	CHECK(IsRefused("Zg==", Encoding::Base64Url));
	CHECK(IsRefused("Zm8=", Encoding::Base64Url));
	CHECK(IsRefused("Z", Encoding::Base64Url));
	CHECK(IsRefused("Zm9vY", Encoding::Base64Url));
	CHECK(IsRefused("Zh", Encoding::Base64Url));
	CHECK(IsRefused("Zm9", Encoding::Base64Url));
}

TEST(RawIsTheBytesThemselves)
{
	std::string bytes("a\0b", 3);
	CHECK(EncodeText(bytes, Encoding::Raw) == bytes);
	CHECK(DecodesTo(bytes, Encoding::Raw, bytes));
}
