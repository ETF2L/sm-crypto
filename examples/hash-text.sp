/**
 * Copyright 2026 ETF2L Contributors, Dave
 *
 * SMCrypto example: hashing a buffer.
 *
 *   sm_crypto_hash <text>   prints the text's SHA-256 and SHA3-256 digests
 *                           and a short id made from them
 *
 * Crypto.Hash hashes a buffer at once. CryptoDigest hashes a value put
 * together from pieces without copying them into one buffer first.
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <smcrypto>

public Plugin myinfo = {
	name = "SMCrypto example: hash text",
	author = "ETF2L Contributors, Dave",
	description = "Hashes a buffer with SMCrypto",
	version = "1.0.0",
	url = "https://github.com/etf2l/sm-crypto"
};

public void OnPluginStart() {
	RegServerCmd("sm_crypto_hash", Command_Hash, "sm_crypto_hash <text>: prints the text's digests");
}

Action Command_Hash(int args) {
	if (args < 1) {
		PrintToServer("Usage: sm_crypto_hash <text>");
		return Plugin_Handled;
	}
	char text[256];
	GetCmdArgString(text, sizeof(text));

	// A hex digest of SHA-256 needs 2 * 32 digits and the NUL;
	// CRYPTO_MAX_HASH_HEX fits every hash.
	char sha256[CRYPTO_MAX_HASH_HEX];
	Crypto.Hash(CryptoHash_SHA256, text, sha256, sizeof(sha256));
	char sha3[CRYPTO_MAX_HASH_HEX];
	Crypto.Hash(CryptoHash_SHA3_256, text, sha3, sizeof(sha3));
	PrintToServer("SHA-256:  %s", sha256);
	PrintToServer("SHA3-256: %s", sha3);

	// A short id for the text, e.g. for a cache file name: the digest of
	// "<length>:<text>" in base64url, cut to 16 characters (96 bits).
	CryptoDigest digest = new CryptoDigest(CryptoHash_SHA256);
	char length[16];
	IntToString(strlen(text), length, sizeof(length));
	digest.Update(length);
	digest.Update(":");
	digest.Update(text);
	char id[64];
	digest.Final(id, sizeof(id), CryptoEncoding_Base64Url);
	delete digest;
	id[16] = '\0';
	PrintToServer("Id:       %s", id);
	return Plugin_Handled;
}
