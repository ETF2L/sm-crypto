/* Copyright 2026 ETF2L Contributors, Dave */
#include "encoding.h"

namespace smcrypto {

namespace {

constexpr char kHexDigits[] = "0123456789abcdef";
constexpr char kBase64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr char kBase64UrlAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
constexpr int kInvalid = -1;

int HexValue(uint8_t digit)
{
	if (digit >= '0' && digit <= '9')
		return digit - '0';
	if (digit >= 'a' && digit <= 'f')
		return digit - 'a' + 10;
	if (digit >= 'A' && digit <= 'F')
		return digit - 'A' + 10;
	return kInvalid;
}

int Base64Value(uint8_t character, bool isUrl)
{
	if (character >= 'A' && character <= 'Z')
		return character - 'A';
	if (character >= 'a' && character <= 'z')
		return character - 'a' + 26;
	if (character >= '0' && character <= '9')
		return character - '0' + 52;
	if (character == (isUrl ? '-' : '+'))
		return 62;
	if (character == (isUrl ? '_' : '/'))
		return 63;
	return kInvalid;
}

SecretBytes EncodeHex(ByteView bytes)
{
	SecretBytes text;
	text.reserve(bytes.size * 2);
	for (size_t i = 0; i < bytes.size; i++) {
		text.push_back(static_cast<uint8_t>(kHexDigits[bytes.data[i] >> 4]));
		text.push_back(static_cast<uint8_t>(kHexDigits[bytes.data[i] & 0x0f]));
	}
	return text;
}

std::optional<SecretBytes> DecodeHex(ByteView text)
{
	if (text.size % 2 != 0)
		return std::nullopt;
	SecretBytes bytes;
	bytes.reserve(text.size / 2);
	for (size_t i = 0; i < text.size; i += 2) {
		int high = HexValue(text.data[i]);
		int low = HexValue(text.data[i + 1]);
		if (high == kInvalid || low == kInvalid)
			return std::nullopt;
		bytes.push_back(static_cast<uint8_t>((high << 4) | low));
	}
	return bytes;
}

SecretBytes EncodeBase64(ByteView bytes, bool isUrl)
{
	const char *alphabet = isUrl ? kBase64UrlAlphabet : kBase64Alphabet;
	SecretBytes text;
	Encoding encoding = isUrl ? Encoding::Base64Url : Encoding::Base64;
	text.reserve(static_cast<size_t>(EncodedLength(bytes.size, encoding)));
	size_t i = 0;
	for (; i + 3 <= bytes.size; i += 3) {
		uint32_t group = (uint32_t(bytes.data[i]) << 16) | (uint32_t(bytes.data[i + 1]) << 8) | bytes.data[i + 2];
		for (int shift = 18; shift >= 0; shift -= 6)
			text.push_back(static_cast<uint8_t>(alphabet[(group >> shift) & 0x3f]));
	}
	size_t rest = bytes.size - i;
	if (rest == 0)
		return text;
	uint32_t group = uint32_t(bytes.data[i]) << 16;
	if (rest == 2)
		group |= uint32_t(bytes.data[i + 1]) << 8;
	/* One byte makes two characters, two bytes make three. */
	for (size_t k = 0; k <= rest; k++)
		text.push_back(static_cast<uint8_t>(alphabet[(group >> (18 - 6 * k)) & 0x3f]));
	if (!isUrl)
		text.insert(text.end(), 3 - rest, static_cast<uint8_t>('='));
	return text;
}

std::optional<SecretBytes> DecodeBase64(ByteView text, bool isUrl)
{
	size_t length = text.size;
	if (!isUrl) {
		if (length % 4 != 0)
			return std::nullopt;
		/* At most two "=", and only at the end. */
		size_t padding = 0;
		while (padding < 2 && padding < length && text.data[length - 1 - padding] == '=')
			padding++;
		length -= padding;
	}
	/* A group of one character holds no whole byte. */
	if (length % 4 == 1)
		return std::nullopt;

	SecretBytes bytes;
	bytes.reserve(length / 4 * 3 + 2);
	uint32_t group = 0;
	size_t inGroup = 0;
	for (size_t i = 0; i < length; i++) {
		int value = Base64Value(text.data[i], isUrl);
		if (value == kInvalid)
			return std::nullopt;
		group = (group << 6) | static_cast<uint32_t>(value);
		if (++inGroup < 4)
			continue;
		bytes.push_back(static_cast<uint8_t>(group >> 16));
		bytes.push_back(static_cast<uint8_t>(group >> 8));
		bytes.push_back(static_cast<uint8_t>(group));
		group = 0;
		inGroup = 0;
	}
	if (inGroup == 0)
		return bytes;

	/* Two characters hold one byte and 4 spare bits, three hold two bytes and
	 * 2 spare bits; spare bits must be zero. */
	size_t spareBits = inGroup == 2 ? 4 : 2;
	if ((group & ((1u << spareBits) - 1)) != 0)
		return std::nullopt;
	group >>= spareBits;
	if (inGroup == 3)
		bytes.push_back(static_cast<uint8_t>(group >> 8));
	bytes.push_back(static_cast<uint8_t>(group));
	return bytes;
}

} // namespace

uint64_t EncodedLength(uint64_t size, Encoding encoding)
{
	switch (encoding) {
	case Encoding::Hex:
		return size * 2;
	case Encoding::Base64:
		return (size + 2) / 3 * 4;
	case Encoding::Base64Url:
		return size / 3 * 4 + (size % 3 == 0 ? 0 : size % 3 + 1);
	case Encoding::Raw:
		return size;
	}
	return 0;
}

SecretBytes Encode(ByteView bytes, Encoding encoding)
{
	switch (encoding) {
	case Encoding::Hex:
		return EncodeHex(bytes);
	case Encoding::Base64:
		return EncodeBase64(bytes, false);
	case Encoding::Base64Url:
		return EncodeBase64(bytes, true);
	case Encoding::Raw:
		break;
	}
	return SecretBytes(bytes.data, bytes.data + bytes.size);
}

std::optional<SecretBytes> Decode(ByteView text, Encoding encoding)
{
	switch (encoding) {
	case Encoding::Hex:
		return DecodeHex(text);
	case Encoding::Base64:
		return DecodeBase64(text, false);
	case Encoding::Base64Url:
		return DecodeBase64(text, true);
	case Encoding::Raw:
		break;
	}
	return SecretBytes(text.data, text.data + text.size);
}

} // namespace smcrypto
