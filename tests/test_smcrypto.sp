/**
 * Copyright 2026 ETF2L Contributors, Dave
 *
 * The tests of smcrypto.inc, run with smrunner (sm-runner) against the
 * built extension:
 *
 *     smrunner test test_smcrypto.smx --extensions <dist>/extensions
 *
 * Every native is called as a plugin calls it: the vectors are the
 * standards' (and the unit tests'), the errors are the ones the include
 * documents, and file jobs run on the extension's worker thread, waited for
 * with Runner.WaitUntil.
 */

// no critic (ProhibitObfuscatedStrings, ProhibitLongFiles)
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <smcrypto>
#include <smrunner>

/* ------------------------------------------------------------------ helpers */

/* Runs failing, which must stop with a native error containing text. */
void ExpectNativeError(Function failing, const char[] text) {
	Runner.ExpectError(text);
	Call_StartFunction(null, failing);
	Call_Finish();
}

/* A hex text's bytes into bytes; returns their number. */
int FromHex(const char[] hex, char[] bytes, int maxlength) {
	int length = Crypto.Decode(hex, bytes, maxlength, CryptoEncoding_Hex);
	Assert.True(length >= 0, "\"%s\" is hex", hex);
	return length;
}

/* Fills bytes with values, one byte each, as char arrays take no lists. */
void SetBytes(char[] bytes, const int[] values, int count) {
	for (int i = 0; i < count; i++) {
		bytes[i] = values[i];
	}
}

void WriteTestFile(const char[] path, const char[] content) {
	File file = OpenFile(path, "wb");
	Assert.True(file != null, "%s can be written", path);
	file.WriteString(content, false);
	delete file;
}

/* ------------------------------------------------------------------ hashing */

/* "abc" hashed, indexed by CryptoHash. */
static const char g_abcDigests[][] = {
	"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	"23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
	"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
	"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
	"e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
	"3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
	"ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
	"b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
	"a9993e364706816aba3e25717850c26c9cd0d89d",
	"900150983cd24fb0d6963f7d28e17f72",
};

public void Test_EveryHashMatchesItsStandardVector() {
	char hex[CRYPTO_MAX_HASH_HEX];
	for (int hash = 0; hash < sizeof(g_abcDigests); hash++) {
		int written = Crypto.Hash(view_as<CryptoHash>(hash), "abc", hex, sizeof(hex));
		Assert.StrEqual(hex, g_abcDigests[hash], "CryptoHash %d", hash);
		Assert.Equal(written, 2 * Crypto.HashSize(view_as<CryptoHash>(hash)));
	}
}

public void Test_HashWritesEveryEncoding() {
	char output[64];
	Assert.Equal(Crypto.Hash(CryptoHash_SHA256, "abc", output, sizeof(output), CryptoEncoding_Base64), 44);
	Assert.StrEqual(output, "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=");
	Assert.Equal(Crypto.Hash(CryptoHash_SHA256, "abc", output, sizeof(output), CryptoEncoding_Base64Url), 43);
	Assert.StrEqual(output, "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");

	char raw[33];
	Assert.Equal(Crypto.Hash(CryptoHash_SHA256, "abc", raw, sizeof(raw), CryptoEncoding_Raw), 32);
	char again[CRYPTO_MAX_HASH_HEX];
	Crypto.Encode(raw, again, sizeof(again), CryptoEncoding_Hex, 32);
	Assert.StrEqual(again, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

public void Test_HashTakesBinaryDataByLength() {
	char data[4];
	int values[] = {'a', 0, 'b', 0};
	SetBytes(data, values, sizeof(values));
	char hex[CRYPTO_MAX_HASH_HEX];
	Crypto.Hash(CryptoHash_SHA256, data, hex, sizeof(hex), .dataLength = 3);
	char upToNul[CRYPTO_MAX_HASH_HEX];
	Crypto.Hash(CryptoHash_SHA256, data, upToNul, sizeof(upToNul));
	char onlyA[CRYPTO_MAX_HASH_HEX];
	Crypto.Hash(CryptoHash_SHA256, "a", onlyA, sizeof(onlyA));
	Assert.StrEqual(upToNul, onlyA, "-1 hashes up to the NUL");
	Assert.False(StrEqual(hex, onlyA), "an explicit length hashes the NUL and what follows");
	Crypto.Hash(CryptoHash_SHA256, "", hex, sizeof(hex));
	Assert.StrEqual(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

void HashIntoTooSmallBuffer() {
	char hex[64];
	Crypto.Hash(CryptoHash_SHA256, "abc", hex, sizeof(hex));
}

void HashWithInvalidHash() {
	char hex[CRYPTO_MAX_HASH_HEX];
	Crypto.Hash(view_as<CryptoHash>(10), "abc", hex, sizeof(hex));
}

void HashWithInvalidEncoding() {
	char hex[CRYPTO_MAX_HASH_HEX];
	Crypto.Hash(CryptoHash_SHA256, "abc", hex, sizeof(hex), view_as<CryptoEncoding>(4));
}

void HashWithNegativeLength() {
	char hex[CRYPTO_MAX_HASH_HEX];
	Crypto.Hash(CryptoHash_SHA256, "abc", hex, sizeof(hex), .dataLength = -2);
}

void HashPastThePluginsMemory() {
	char hex[CRYPTO_MAX_HASH_HEX];
	Crypto.Hash(CryptoHash_SHA256, "abc", hex, sizeof(hex), .dataLength = 0x7fffffff);
}

public void Test_HashRefusesWrongArguments() {
	ExpectNativeError(HashIntoTooSmallBuffer, "a buffer of 64 bytes is too small, 65 are needed");
	ExpectNativeError(HashWithInvalidHash, "Invalid CryptoHash 10");
	ExpectNativeError(HashWithInvalidEncoding, "Invalid CryptoEncoding 4");
	ExpectNativeError(HashWithNegativeLength, "invalid length -2");
	ExpectNativeError(HashPastThePluginsMemory, "do not fit into the plugin's memory");
}

public void Test_SizesAreTheIncludesConstants() {
	Assert.Equal(Crypto.HashSize(CryptoHash_SHA512), CRYPTO_MAX_HASH_SIZE);
	Assert.Equal(Crypto.EncodedSize(CRYPTO_MAX_HASH_SIZE, CryptoEncoding_Hex), CRYPTO_MAX_HASH_HEX);
	Assert.Equal(Crypto.HashSize(CryptoHash_MD5), 16);
	Assert.Equal(Crypto.EncodedSize(0, CryptoEncoding_Base64), 1);
	Assert.Equal(Crypto.EncodedSize(1, CryptoEncoding_Base64), 5);
	Assert.Equal(Crypto.EncodedSize(1, CryptoEncoding_Base64Url), 3);
	Assert.Equal(Crypto.EncodedSize(5, CryptoEncoding_Raw), 6);
	Assert.Equal(Crypto.SealedSize(0, CryptoEncoding_Raw), CRYPTO_SEAL_OVERHEAD + 1);
	Assert.Equal(Crypto.SealedSize(3), Crypto.EncodedSize(3 + CRYPTO_SEAL_OVERHEAD, CryptoEncoding_Base64));
	Assert.Equal(Crypto.SealedSize(3, CryptoEncoding_Hex, CryptoCipher_ChaCha20Poly1305),
	             Crypto.EncodedSize(3 + CRYPTO_SEAL_OVERHEAD, CryptoEncoding_Hex));
}

void EncodedSizeTooLarge() {
	Crypto.EncodedSize(0x7fffffff, CryptoEncoding_Hex);
}

public void Test_SupportTellsEveryValueOfTheInclude() {
	for (int hash = 0; hash <= view_as<int>(CryptoHash_MD5); hash++) {
		Assert.True(Crypto.IsHashSupported(view_as<CryptoHash>(hash)), "CryptoHash %d", hash);
	}
	for (int cipher = 0; cipher <= view_as<int>(CryptoCipher_AES128GCM); cipher++) {
		Assert.True(Crypto.IsCipherSupported(view_as<CryptoCipher>(cipher)), "CryptoCipher %d", cipher);
	}
	Assert.False(Crypto.IsHashSupported(view_as<CryptoHash>(10)), "a value of a later include");
	Assert.False(Crypto.IsHashSupported(view_as<CryptoHash>(-1)));
	Assert.False(Crypto.IsCipherSupported(view_as<CryptoCipher>(3)));
}

public void Test_EncodedSizeRefusesSizesAPluginCannotHold() {
	ExpectNativeError(EncodedSizeTooLarge, "more than 2^31 - 1 bytes");
}

/* --------------------------------------------------------------- encodings */

public void Test_EncodeAndDecodeRoundTrip() {
	char text[32];
	Assert.Equal(Crypto.Encode("foobar", text, sizeof(text), CryptoEncoding_Base64), 8);
	Assert.StrEqual(text, "Zm9vYmFy");
	char bytes[32];
	Assert.Equal(Crypto.Decode(text, bytes, sizeof(bytes), CryptoEncoding_Base64), 6);
	Assert.StrEqual(bytes, "foobar");
	Crypto.Encode("f", text, sizeof(text), CryptoEncoding_Base64Url);
	Assert.StrEqual(text, "Zg");
	Crypto.Encode("\xff", text, sizeof(text), CryptoEncoding_Hex);
	Assert.StrEqual(text, "ff");
	Assert.Equal(Crypto.Decode("DEADbeef", bytes, sizeof(bytes), CryptoEncoding_Hex), 4);
	Assert.Equal(bytes[0], 0xde);
	Assert.Equal(bytes[3], 0xef);
	Assert.Equal(bytes[4], 0, "a NUL follows the bytes");
}

void DecodeIntoNoBuffer() {
	char bytes[8];
	Crypto.Decode("Zg==", bytes, 0, CryptoEncoding_Base64);
}

public void Test_EncodingNothingWritesTheNul() {
	char text[4] = "xyz";
	Assert.Equal(Crypto.Encode("", text, sizeof(text), CryptoEncoding_Base64), 0);
	Assert.Equal(text[0], 0);
	ExpectNativeError(DecodeIntoNoBuffer, "Invalid buffer size 0");
}

public void Test_DecodeTellsInvalidTextByItsResult() {
	char bytes[8];
	Assert.Equal(Crypto.Decode("Zg=", bytes, sizeof(bytes), CryptoEncoding_Base64), -1, "missing padding");
	Assert.Equal(Crypto.Decode("Zh==", bytes, sizeof(bytes), CryptoEncoding_Base64), -1, "non-zero spare bits");
	Assert.Equal(Crypto.Decode("Zg==", bytes, sizeof(bytes), CryptoEncoding_Base64Url), -1, "padding in base64url");
	Assert.Equal(Crypto.Decode("abc", bytes, sizeof(bytes), CryptoEncoding_Hex), -1, "odd hex");
	Assert.Equal(Crypto.Decode("Zm9vYmFy", bytes, 6, CryptoEncoding_Base64), -1, "six bytes and the NUL need 7");
	Assert.Equal(Crypto.Decode("Zm9vYmFy", bytes, 7, CryptoEncoding_Base64), 6);
	Assert.Equal(Crypto.Decode("", bytes, sizeof(bytes), CryptoEncoding_Hex), 0);
}

void DecodeRawWithoutLength() {
	char bytes[8];
	Crypto.Decode("abc", bytes, sizeof(bytes), CryptoEncoding_Raw);
}

public void Test_RawInputsNeedTheirLength() {
	ExpectNativeError(DecodeRawWithoutLength, "CryptoEncoding_Raw needs the value's length");
	char raw[3];
	int values[] = {'x', 0, 'y'};
	SetBytes(raw, values, sizeof(values));
	char bytes[8];
	Assert.Equal(Crypto.Decode(raw, bytes, sizeof(bytes), CryptoEncoding_Raw, 3), 3);
	Assert.Equal(bytes[1], 0);
	Assert.Equal(bytes[2], 'y');
}

/* ------------------------------------------------------ random, comparison */

public void Test_RandomBytesHaveTheirSizeAndDiffer() {
	char first[33];
	Assert.Equal(Crypto.Random(first, sizeof(first), 16), 32);
	char second[33];
	Crypto.Random(second, sizeof(second), 16);
	Assert.Equal(strlen(first), 32);
	Assert.False(StrEqual(first, second), "two draws of 16 bytes differ");
	char token[32];
	Assert.Equal(Crypto.Random(token, sizeof(token), 16, CryptoEncoding_Base64Url), 22);
}

public void Test_RandomIntStaysInItsBounds() {
	bool seen[7];
	for (int i = 0; i < 2000; i++) {
		int value = Crypto.RandomInt(-3, 3);
		Assert.True(value >= -3 && value <= 3, "%d is from -3 to 3", value);
		seen[value + 3] = true;
	}
	for (int i = 0; i < sizeof(seen); i++) {
		Assert.True(seen[i], "%d was drawn", i - 3);
	}
	Assert.Equal(Crypto.RandomInt(5, 5), 5);
	Crypto.RandomInt(cellmin, cellmax);
}

void RandomIntReversed() {
	Crypto.RandomInt(2, 1);
}

void RandomTooMany() {
	char output[16];
	Crypto.Random(output, sizeof(output), 65537);
}

public void Test_RandomRefusesWrongArguments() {
	ExpectNativeError(RandomIntReversed, "min 2 is greater than max 1");
	ExpectNativeError(RandomTooMany, "Invalid number of random bytes 65537");
}

public void Test_EqualComparesBytes() {
	char a[4];
	int first[] = {1, 0, 2, 3};
	SetBytes(a, first, 4);
	char b[4];
	SetBytes(b, first, 4);
	char c[4];
	int other[] = {1, 0, 2, 4};
	SetBytes(c, other, 4);
	Assert.True(Crypto.Equal(a, b, 4));
	Assert.False(Crypto.Equal(a, c, 4));
	Assert.True(Crypto.Equal(a, c, 3));
	Assert.True(Crypto.Equal(a, c, 0));
}

public void Test_ErrorStringNamesErrors() {
	char name[32];
	Crypto.ErrorString(CryptoError_NotAFile, name, sizeof(name));
	Assert.StrEqual(name, "CryptoError_NotAFile");
}

/* --------------------------------------------------------------------- keys */

public void Test_KeysExportWhatTheyImport() {
	CryptoKey generated = CryptoKey.Generate();
	Assert.Equal(generated.Length, CRYPTO_KEY_SIZE);
	char text[64];
	Assert.Equal(generated.Export(text, sizeof(text)), 44);
	CryptoKey imported = CryptoKey.Import(text);
	Assert.True(imported != null);
	char again[64];
	imported.Export(again, sizeof(again));
	Assert.StrEqual(again, text);
	delete generated;
	delete imported;

	CryptoKey secret = CryptoKey.FromString("webhook secret");
	Assert.Equal(secret.Length, 14);
	secret.Export(text, sizeof(text), CryptoEncoding_Raw);
	Assert.StrEqual(text, "webhook secret");
	delete secret;
}

public void Test_ImportTellsInvalidKeysByNull() {
	Assert.True(CryptoKey.Import("not base64!") == null);
	Assert.True(CryptoKey.Import("") == null, "an empty key");
	char tooLong[2 * CRYPTO_MAX_KEY_SIZE + 3];
	for (int i = 0; i < sizeof(tooLong) - 1; i++) {
		tooLong[i] = 'a';
	}
	Assert.True(CryptoKey.Import(tooLong, CryptoEncoding_Hex) == null, "1025 bytes");
	tooLong[2 * CRYPTO_MAX_KEY_SIZE] = 0;
	CryptoKey longest = CryptoKey.Import(tooLong, CryptoEncoding_Hex);
	Assert.Equal(longest.Length, CRYPTO_MAX_KEY_SIZE);
	delete longest;
}

public void Test_KeysAndDigestsCannotBeCloned() {
	CryptoKey key = CryptoKey.Generate();
	Assert.True(CloneHandle(key) == null, "not even by their owner");
	CryptoDigest digest = new CryptoDigest(CryptoHash_SHA256);
	Assert.True(CloneHandle(digest) == null);
	delete key;
	delete digest;
}

CryptoKey g_holdersKey;

void ExportHoldersKey() {
	char output[64];
	g_holdersKey.Export(output, sizeof(output));
}

public void Test_AnotherPluginsKeyIsOutOfReach() {
	/* key-holder.smx keeps a key in g_key; its handle value could leak. */
	Handle holder = FindPluginByFile("key-holder.smx");
	Assert.True(holder != null, "key-holder.smx runs");
	g_holdersKey = view_as<CryptoKey>(Runner.GetPluginValue(holder, "g_key"));
	ExpectNativeError(ExportHoldersKey, "Invalid CryptoKey handle");
	Assert.True(CloneHandle(g_holdersKey) == null, "the key cannot be taken by a clone");
}

/* Heap arrays lie below the free gap, the stack above it: a maxlength that
 * reaches over the gap would write into the VM's saved frames. */
char g_largeSource[20000];
int g_writeLength;
int g_acceptedWrites;

void WriteIntoSmallHeapArray() {
	char[] small = new char[4];
	Crypto.Encode(g_largeSource, small, g_writeLength + 1, CryptoEncoding_Raw, g_writeLength);
	g_acceptedWrites++;
}

void CallWithAFrame() {
	int local = 7; // no critic (RequireLateDeclarations) - the call needs a stack frame with a local
	WriteIntoSmallHeapArray();
	local++;
}

public void Test_ASpanCannotCrossFromTheHeapIntoTheStack() {
	for (int i = 0; i < sizeof(g_largeSource); i++) {
		g_largeSource[i] = 'A';
	}
	for (g_writeLength = 64; g_writeLength < sizeof(g_largeSource); g_writeLength += 64) {
		Runner.ExpectError("do not fit into the plugin's memory");
		Call_StartFunction(null, CallWithAFrame);
		Call_Finish();
	}
	Assert.Equal(g_acceptedWrites, 0, "no write past the 4-byte heap array was taken");
}

public void Test_TheLongestKeyMacsAndDerives() {
	char hex[2 * CRYPTO_MAX_KEY_SIZE + 1];
	for (int i = 0; i < sizeof(hex) - 1; i++) {
		hex[i] = 'a';
	}
	CryptoKey key = CryptoKey.Import(hex, CryptoEncoding_Hex);
	char mac[CRYPTO_MAX_HASH_HEX];
	Assert.Equal(key.Hmac(CryptoHash_SHA256, "message", mac, sizeof(mac)), 64);
	Assert.True(key.HmacVerify(CryptoHash_SHA256, "message", mac));
	CryptoKey derived = key.Derive("purpose", CRYPTO_MAX_KEY_SIZE, .hash = CryptoHash_SHA512);
	Assert.Equal(derived.Length, CRYPTO_MAX_KEY_SIZE);
	delete derived;
	delete key;
}

void GenerateEmptyKey() {
	CryptoKey.Generate(0);
}

void KeyFromEmptyString() {
	CryptoKey.FromString("");
}

void UseDeletedKey() {
	CryptoKey key = CryptoKey.Generate();
	delete key;
	CryptoKey stale = view_as<CryptoKey>(0x12345);
	char output[64];
	stale.Export(output, sizeof(output));
}

public void Test_KeysRefuseWrongArguments() {
	ExpectNativeError(GenerateEmptyKey, "Invalid key length 0");
	ExpectNativeError(KeyFromEmptyString, "A secret of 0 bytes is no key");
	ExpectNativeError(UseDeletedKey, "Invalid CryptoKey handle");
}

public void Test_DeriveMatchesRfc5869() {
	CryptoKey key = CryptoKey.Import("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", CryptoEncoding_Hex);
	char salt[14];
	int saltLength = FromHex("000102030405060708090a0b0c", salt, sizeof(salt));
	char info[11];
	int infoLength = FromHex("f0f1f2f3f4f5f6f7f8f9", info, sizeof(info));
	CryptoKey derived = key.Derive(info, 42, salt, CryptoHash_SHA256, infoLength, saltLength);
	char okm[100];
	derived.Export(okm, sizeof(okm), CryptoEncoding_Hex);
	Assert.StrEqual(okm, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
	delete derived;

	CryptoKey noSalt = key.Derive("", 42);
	noSalt.Export(okm, sizeof(okm), CryptoEncoding_Hex);
	Assert.StrEqual(okm, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
	delete noSalt;
	delete key;
}

public void Test_DerivedKeysDifferPerPurpose() {
	CryptoKey master = CryptoKey.Generate();
	CryptoKey tokens = master.Derive("tokens v1"), notes = master.Derive("notes v1");
	CryptoKey tokensAgain = master.Derive("tokens v1");
	char a[64];
	tokens.Export(a, sizeof(a));
	char b[64];
	notes.Export(b, sizeof(b));
	char c[64];
	tokensAgain.Export(c, sizeof(c));
	Assert.False(StrEqual(a, b));
	Assert.StrEqual(a, c);
	delete master;
	delete tokens;
	delete notes;
	delete tokensAgain;
}

void DeriveTooLong() {
	CryptoKey key = CryptoKey.Generate();
	key.Derive("x", 255 * 16 + 1, "", CryptoHash_MD5);
}

public void Test_DeriveRefusesLengthsHkdfCannotMake() {
	ExpectNativeError(DeriveTooLong, "Invalid key length 4081: 1 to 1024 bytes with MD5");
}

/* --------------------------------------------------------------------- HMAC */

public void Test_HmacMatchesRfc4231() {
	CryptoKey key = CryptoKey.FromString("Jefe");
	char mac[CRYPTO_MAX_HASH_HEX];
	key.Hmac(CryptoHash_SHA256, "what do ya want for nothing?", mac, sizeof(mac));
	Assert.StrEqual(mac, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
	Assert.True(key.HmacVerify(CryptoHash_SHA256, "what do ya want for nothing?", mac));
	Assert.True(key.HmacVerify(CryptoHash_SHA256, "what do ya want for nothing?",
	                           "5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843"), "upper case hex");
	delete key;
}

public void Test_HmacVerifyRefusesEveryOtherMac() {
	CryptoKey key = CryptoKey.Generate();
	char mac[CRYPTO_MAX_HASH_HEX];
	key.Hmac(CryptoHash_SHA256, "message", mac, sizeof(mac));
	Assert.False(key.HmacVerify(CryptoHash_SHA256, "massage", mac), "another message");
	Assert.False(key.HmacVerify(CryptoHash_SHA512, "message", mac), "another hash");
	mac[63] = mac[63] == '0' ? '1' : '0';
	Assert.False(key.HmacVerify(CryptoHash_SHA256, "message", mac), "a changed digit");
	mac[62] = 0;
	Assert.False(key.HmacVerify(CryptoHash_SHA256, "message", mac), "a shorter MAC");
	Assert.False(key.HmacVerify(CryptoHash_SHA256, "message", "zz"), "no hex");
	Assert.False(key.HmacVerify(CryptoHash_SHA256, "message", ""), "nothing");

	char raw[33];
	key.Hmac(CryptoHash_SHA256, "message", raw, sizeof(raw), CryptoEncoding_Raw);
	Assert.True(key.HmacVerify(CryptoHash_SHA256, "message", raw, CryptoEncoding_Raw, .macLength = 32));
	delete key;
}

/* ---------------------------------------------------------- sealed messages */

public void Test_SealedMessagesOpenWithTheirKey() {
	CryptoKey key = CryptoKey.Generate();
	char message[256], opened[256];
	for (int cipher = 0; cipher < 2; cipher++) {
		int written = key.Seal("meet at mid", message, sizeof(message), .cipher = view_as<CryptoCipher>(cipher));
		Assert.Equal(written, Crypto.SealedSize(11) - 1);
		Assert.Equal(key.Open(message, opened, sizeof(opened)), 11);
		Assert.StrEqual(opened, "meet at mid");
	}
	CryptoKey aes128Key = CryptoKey.Generate(16);
	aes128Key.Seal("", message, sizeof(message), CryptoEncoding_Hex, CryptoCipher_AES128GCM);
	Assert.Equal(strlen(message), 2 * CRYPTO_SEAL_OVERHEAD);
	Assert.Equal(aes128Key.Open(message, opened, sizeof(opened), CryptoEncoding_Hex), 0);
	delete aes128Key;
	delete key;
}

public void Test_SealedMessagesOpenOnlyUnchanged() {
	CryptoKey key = CryptoKey.Generate(), other = CryptoKey.Generate();
	char message[256];
	key.Seal("secret", message, sizeof(message), CryptoEncoding_Hex, .aad = "STEAM_0:1:23");
	char opened[256];
	Assert.Equal(key.Open(message, opened, sizeof(opened), CryptoEncoding_Hex, "STEAM_0:1:23"), 6);
	Assert.Equal(key.Open(message, opened, sizeof(opened), CryptoEncoding_Hex, "STEAM_0:1:24"), -1, "other aad");
	Assert.Equal(key.Open(message, opened, sizeof(opened), CryptoEncoding_Hex), -1, "no aad");
	Assert.Equal(other.Open(message, opened, sizeof(opened), CryptoEncoding_Hex, "STEAM_0:1:23"), -1, "other key");
	Assert.Equal(key.Open(message, opened, sizeof(opened), CryptoEncoding_Base64, "STEAM_0:1:23"), -1,
	             "other encoding");
	for (int i = 0; message[i] != 0; i++) {
		char changed[256];
		strcopy(changed, sizeof(changed), message);
		changed[i] = changed[i] == 'a' ? 'b' : 'a';
		Assert.Equal(key.Open(changed, opened, sizeof(opened), CryptoEncoding_Hex, "STEAM_0:1:23"), -1,
		             "digit %d changed", i);
	}
	Assert.Equal(key.Open("", opened, sizeof(opened)), -1, "nothing");
	delete key;
	delete other;
}

public void Test_OpenReadsMessagesSealedElsewhere() {
	/* tools/sealed_vectors.py of the extension's unit tests. */
	CryptoKey key = CryptoKey.Import("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
	                                 CryptoEncoding_Hex);
	char opened[64];
	int length =
		key.Open(
			"026465666768696a6b6c6d6e6fd7e6bb4dbcd62ce5e6d9833b508f11009c1dede9799401b2abcf70bcc98246d66b3850e64aa600",
			opened, sizeof(opened), CryptoEncoding_Hex, "STEAM_0:1:23");
	Assert.Equal(length, 23);
	Assert.StrEqual(opened, "SMCrypto sealed message");
	delete key;
}

public void Test_SealedMessagesCarryBinaryPlaintexts() {
	CryptoKey key = CryptoKey.Generate();
	char plaintext[5];
	int values[] = {0, 1, 0, 2, 0};
	SetBytes(plaintext, values, sizeof(values));
	char message[128];
	int written = key.Seal(plaintext, message, sizeof(message), CryptoEncoding_Raw, .plaintextLength = 5);
	Assert.Equal(written, 5 + CRYPTO_SEAL_OVERHEAD);
	char opened[16];
	Assert.Equal(key.Open(message, opened, sizeof(opened), CryptoEncoding_Raw, .messageLength = written), 5);
	Assert.True(Crypto.Equal(opened, plaintext, 5));
	/* A buffer as large as the sealed message always fits its plaintext. */
	char exact[5 + CRYPTO_SEAL_OVERHEAD];
	Assert.Equal(key.Open(message, exact, sizeof(exact), CryptoEncoding_Raw, .messageLength = written), 5);
	delete key;
}

void SealWithKeyOfWrongSize() {
	CryptoKey key = CryptoKey.Generate(16);
	char message[128];
	key.Seal("x", message, sizeof(message));
}

void OpenIntoTooSmallBuffer() {
	CryptoKey key = CryptoKey.Generate();
	char message[128];
	key.Seal("four", message, sizeof(message));
	char opened[4];
	key.Open(message, opened, sizeof(opened));
}

void SealWithInvalidCipher() {
	CryptoKey key = CryptoKey.Generate();
	char message[128];
	key.Seal("x", message, sizeof(message), .cipher = view_as<CryptoCipher>(3));
}

public void Test_SealRefusesWrongArguments() {
	ExpectNativeError(SealWithKeyOfWrongSize, "AES-256-GCM needs a key of 32 bytes, this key has 16");
	ExpectNativeError(OpenIntoTooSmallBuffer, "a buffer of 4 bytes is too small, 5 are needed");
	ExpectNativeError(SealWithInvalidCipher, "Invalid CryptoCipher 3");
}

/* ------------------------------------------------------------------ digests */

public void Test_ADigestHashesItsPieces() {
	CryptoDigest digest = new CryptoDigest(CryptoHash_SHA256);
	Assert.Equal(digest.Hash, CryptoHash_SHA256);
	digest.Update("a");
	digest.Update("");
	digest.Update("bc");
	Assert.False(digest.IsFinished);
	char hex[CRYPTO_MAX_HASH_HEX];
	Assert.Equal(digest.Final(hex, sizeof(hex)), 64);
	Assert.True(digest.IsFinished);
	Assert.StrEqual(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	delete digest;
}

public void Test_AnHmacDigestMacsLikeTheKey() {
	CryptoKey key = CryptoKey.Generate();
	char expected[CRYPTO_MAX_HASH_HEX];
	key.Hmac(CryptoHash_SHA512, "steamid=1;expires=99", expected, sizeof(expected));
	CryptoDigest digest = CryptoDigest.Hmac(CryptoHash_SHA512, key);
	delete key;
	digest.Update("steamid=1;");
	digest.Update("expires=99");
	char actual[CRYPTO_MAX_HASH_HEX];
	digest.Final(actual, sizeof(actual));
	Assert.StrEqual(actual, expected, "the digest kept its own copy of the key");
	delete digest;
}

public void Test_VerifyEndsADigest() {
	CryptoDigest digest = new CryptoDigest(CryptoHash_MD5);
	digest.Update("abc");
	Assert.True(digest.Verify("900150983cd24fb0d6963f7d28e17f72"));
	Assert.True(digest.IsFinished);
	delete digest;
	digest = new CryptoDigest(CryptoHash_MD5);
	digest.Update("abd");
	Assert.False(digest.Verify("900150983cd24fb0d6963f7d28e17f72"));
	delete digest;
}

CryptoDigest g_openDigest;

void FinalIntoTooSmallBuffer() {
	char hex[64];
	g_openDigest.Final(hex, sizeof(hex));
}

void UpdateFinishedDigest() {
	g_openDigest.Update("more");
}

public void Test_ATooSmallBufferLeavesTheDigestOpen() {
	g_openDigest = new CryptoDigest(CryptoHash_SHA256);
	g_openDigest.Update("abc");
	ExpectNativeError(FinalIntoTooSmallBuffer, "a buffer of 64 bytes is too small, 65 are needed");
	Assert.False(g_openDigest.IsFinished);
	char hex[CRYPTO_MAX_HASH_HEX];
	g_openDigest.Final(hex, sizeof(hex));
	Assert.StrEqual(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	ExpectNativeError(UpdateFinishedDigest, "The CryptoDigest is finished");
	delete g_openDigest;
}

/* -------------------------------------------------------------------- files */

int g_callbacks;
CryptoError g_error;
char g_path[PLATFORM_MAX_PATH];
char g_digest[CRYPTO_MAX_HASH_HEX];
int g_digestLength;
any g_data;
CryptoError g_errorOfData[3];
int g_errorOfDataCount;

int g_job;

void OnHashed(int job, CryptoError error, const char[] path, const char[] digest, int digestLength, any data) {
	g_callbacks++;
	g_job = job;
	g_error = error;
	strcopy(g_path, sizeof(g_path), path);
	g_digestLength = digestLength;
	for (int i = 0; i < digestLength && i < sizeof(g_digest); i++) {
		g_digest[i] = digest[i];
	}
	g_data = data;
	if (data >= 0 && data < sizeof(g_errorOfData)) {
		g_errorOfData[data] = error;
	}
	if (error == CryptoError_InvalidPath) {
		g_errorOfDataCount++;
	}
}

bool HasCalledBack(int count) {
	return g_callbacks >= count;
}

public void Test_AFileHashesLikeItsContent() {
	CreateDirectory("crypto-test", 511);
	WriteTestFile("crypto-test/file.txt", "abc");
	int job = Crypto.HashFile(CryptoHash_SHA256, "crypto-test/file.txt", OnHashed, 42);
	Assert.True(job > 0);
	Assert.Equal(g_callbacks, 0, "the callback runs on a later frame");
	Assert.True(Runner.WaitUntil(HasCalledBack, 10.0, 1), "the job called back");
	Assert.Equal(g_error, CryptoError_None);
	Assert.StrEqual(g_path, "crypto-test/file.txt");
	Assert.StrEqual(g_digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	Assert.Equal(g_digestLength, 64);
	Assert.Equal(g_data, 42);
	Assert.Equal(g_job, job, "the callback gets the job's id");
	Assert.False(Crypto.Cancel(job), "a finished job cannot be cancelled");
}

public void Test_AFileDigestComesInAnyEncoding() {
	CreateDirectory("crypto-test", 511);
	WriteTestFile("crypto-test/file.txt", "abc");
	Crypto.HashFile(CryptoHash_SHA256, "crypto-test/file.txt", OnHashed, .encoding = CryptoEncoding_Raw);
	Assert.True(Runner.WaitUntil(HasCalledBack, 10.0, 1));
	Assert.Equal(g_digestLength, 32);
	char expected[33];
	Crypto.Hash(CryptoHash_SHA256, "abc", expected, sizeof(expected), CryptoEncoding_Raw);
	Assert.True(Crypto.Equal(g_digest, expected, 32));
}

public void Test_FileErrorsReachTheCallback() {
	CreateDirectory("crypto-test", 511);
	Crypto.HashFile(CryptoHash_SHA256, "crypto-test/missing", OnHashed);
	Assert.True(Runner.WaitUntil(HasCalledBack, 10.0, 1));
	Assert.Equal(g_error, CryptoError_NotFound);
	Assert.Equal(g_digestLength, 0);
	Crypto.HashFile(CryptoHash_SHA256, "crypto-test", OnHashed);
	Assert.True(Runner.WaitUntil(HasCalledBack, 10.0, 2));
	Assert.Equal(g_error, CryptoError_NotAFile);
}

public void Test_CancelledJobsCallBackAsCancelled() {
	CreateDirectory("crypto-test", 511);
	/* A file of 4 MiB keeps the first job busy while the second waits. */
	File file = OpenFile("crypto-test/big.bin", "wb");
	for (int i = 0; i < 1024; i++) {
		int block[1024];
		file.Write(block, sizeof(block), 4);
	}
	delete file;
	WriteTestFile("crypto-test/small.txt", "small");
	Crypto.HashFile(CryptoHash_SHA512, "crypto-test/big.bin", OnHashed, 1);
	int second = Crypto.HashFile(CryptoHash_SHA256, "crypto-test/small.txt", OnHashed, 2);
	Assert.True(Crypto.Cancel(second));
	Assert.False(Crypto.Cancel(123456), "no such job");
	Assert.True(Runner.WaitUntil(HasCalledBack, 20.0, 2), "both jobs called back");
	Assert.Equal(g_errorOfData[2], CryptoError_Cancelled, "the cancelled job");
	Assert.Equal(g_errorOfData[1], CryptoError_None, "the big file");
	Assert.Equal(g_data, 1, "the cancelled job called back first");
}

void HashFileWithoutCallback() {
	Crypto.HashFile(CryptoHash_SHA256, "cfg/server.cfg", INVALID_FUNCTION);
}

public void Test_HashFileTellsPathsOutsideTheGameDirectory() {
	static const char paths[][] = {"../server.cfg", "/etc/passwd", "cfg\\server.cfg", "C:/x", "", "a//b", "./x"};
	int jobs[sizeof(paths)];
	for (int i = 0; i < sizeof(paths); i++) {
		jobs[i] = Crypto.HashFile(CryptoHash_SHA256, paths[i], OnHashed, i);
		Assert.True(jobs[i] > 0, "\"%s\" got a job", paths[i]);
	}
	Assert.Equal(g_callbacks, 0, "even a refused path calls back on a later frame");
	Assert.True(Runner.WaitUntil(HasCalledBack, 10.0, sizeof(paths)));
	Assert.Equal(g_error, CryptoError_InvalidPath);
	Assert.Equal(g_digestLength, 0);
	Assert.Equal(g_errorOfDataCount, sizeof(paths), "every path was refused");
	ExpectNativeError(HashFileWithoutCallback, "Invalid callback function");
}
