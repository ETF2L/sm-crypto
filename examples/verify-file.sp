/**
 * Copyright 2026 ETF2L Contributors, Dave
 *
 * SMCrypto example: hashing a file and checking it against a known digest.
 *
 *   sm_crypto_verify <path> <sha256>   hashes a file below the game
 *                                      directory and tells whether its
 *                                      SHA-256 is the one given
 *
 * Crypto.HashFile hashes on a background thread, so even a large demo does
 * not stall the server; the callback runs on a later frame. The command's
 * caller and the expected digest travel to the callback in a DataPack.
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <smcrypto>

public Plugin myinfo = {
	name = "SMCrypto example: verify a file",
	author = "ETF2L Contributors, Dave",
	description = "Checks a file's SHA-256 with SMCrypto",
	version = "1.0.0",
	url = "https://github.com/etf2l/sm-crypto"
};

public void OnPluginStart() {
	RegAdminCmd("sm_crypto_verify", Command_Verify, ADMFLAG_CONFIG,
	            "sm_crypto_verify <path> <sha256>: checks a file's SHA-256");
}

Action Command_Verify(int client, int args) {
	if (args != 2) {
		ReplyToCommand(client, "Usage: sm_crypto_verify <path> <sha256>");
		return Plugin_Handled;
	}
	char path[PLATFORM_MAX_PATH];
	GetCmdArg(1, path, sizeof(path));
	char expected[CRYPTO_MAX_HASH_HEX];
	GetCmdArg(2, expected, sizeof(expected));

	// The digest to compare with, as bytes: this also refuses a digest that
	// is no hex or has the wrong length before any work is done.
	char expectedBytes[CRYPTO_MAX_HASH_SIZE + 1];
	int length = Crypto.Decode(expected, expectedBytes, sizeof(expectedBytes), CryptoEncoding_Hex);
	if (length != Crypto.HashSize(CryptoHash_SHA256)) {
		ReplyToCommand(client, "\"%s\" is no SHA-256 digest (64 hex digits)", expected);
		return Plugin_Handled;
	}

	DataPack pack = new DataPack();
	pack.WriteCell(client == 0 ? 0 : GetClientUserId(client));
	pack.WriteCell(GetCmdReplySource());
	pack.WriteString(expected);
	// A path outside the game directory is not hashed: the callback gets
	// CryptoError_InvalidPath.
	Crypto.HashFile(CryptoHash_SHA256, path, OnFileHashed, pack, CryptoEncoding_Raw);
	ReplyToCommand(client, "Hashing %s...", path);
	return Plugin_Handled;
}

void OnFileHashed(int job, CryptoError error, const char[] path, const char[] digest, int digestLength,
                  DataPack pack) {
	pack.Reset();
	int userId = pack.ReadCell();
	ReplySource source = pack.ReadCell();
	char expected[CRYPTO_MAX_HASH_HEX];
	pack.ReadString(expected, sizeof(expected));
	delete pack;

	// The caller may have left meanwhile; the server console stays.
	int client = userId == 0 ? 0 : GetClientOfUserId(userId);
	if (userId != 0 && client == 0) {
		return;
	}
	ReplySource previous = SetCmdReplySource(source);
	if (error != CryptoError_None) {
		char name[32];
		Crypto.ErrorString(error, name, sizeof(name));
		ReplyToCommand(client, "%s cannot be hashed: %s", path, name);
	} else {
		char expectedBytes[CRYPTO_MAX_HASH_SIZE + 1];
		Crypto.Decode(expected, expectedBytes, sizeof(expectedBytes), CryptoEncoding_Hex);
		bool isMatch = Crypto.Equal(digest, expectedBytes, digestLength);
		ReplyToCommand(client, "%s %s", path, isMatch ? "matches" : "does NOT match");
	}
	SetCmdReplySource(previous);
}
