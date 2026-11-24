/**
 * Copyright 2026 ETF2L Contributors, Dave
 *
 * The examples (examples/) run through their commands, so the code the
 * documentation shows is known to work:
 *
 *     smrunner test test_examples.smx --extensions <dist>/extensions \
 *         --plugin hash-text.smx --plugin verify-file.smx \
 *         --plugin signed-links.smx --plugin sealed-notes.smx
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <smcrypto>
#include <smrunner>

#define ABC_SHA256 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

void WriteTestFile(const char[] path, const char[] content) {
	File file = OpenFile(path, "wb");
	Assert.True(file != null, "%s can be written", path);
	file.WriteString(content, false);
	delete file;
}

/* ---------------------------------------------------------------- hash-text */

public void Test_HashTextPrintsTheDigests() {
	char output[1024];
	Runner.CommandOutput(output, sizeof(output), "sm_crypto_hash abc");
	Assert.StrContains(output, "SHA-256:  " ... ABC_SHA256);
	Assert.StrContains(output, "SHA3-256: 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
	Assert.StrContains(output, "Id:       ");
}

/* -------------------------------------------------------------- verify-file */

bool HasAnswered(const char[] text) {
	return Runner.ConsoleContains(text);
}

bool IsMatchTold() {
	return HasAnswered("crypto-test/abc.txt matches") || HasAnswered("does NOT match");
}

bool IsMismatchTold() {
	return HasAnswered("does NOT match");
}

bool IsInvalidPathTold() {
	return HasAnswered("../server.cfg cannot be hashed: CryptoError_InvalidPath");
}

bool IsMissingTold() {
	return HasAnswered("cannot be hashed: CryptoError_NotFound");
}

public void Test_VerifyFileTellsAMatch() {
	CreateDirectory("crypto-test", 511);
	WriteTestFile("crypto-test/abc.txt", "abc");
	Runner.Command("sm_crypto_verify crypto-test/abc.txt %s", ABC_SHA256);
	Assert.True(Runner.WaitUntil(IsMatchTold, 10.0), "the file was hashed");
	Assert.ConsoleContains("crypto-test/abc.txt matches");
}

public void Test_VerifyFileTellsAMismatch() {
	CreateDirectory("crypto-test", 511);
	WriteTestFile("crypto-test/abc.txt", "abd");
	Runner.Command("sm_crypto_verify crypto-test/abc.txt %s", ABC_SHA256);
	Assert.True(Runner.WaitUntil(IsMismatchTold, 10.0), "the mismatch was told");
}

public void Test_VerifyFileTellsMissingFilesAndBadDigests() {
	Runner.Command("sm_crypto_verify crypto-test/none.txt %s", ABC_SHA256);
	Assert.True(Runner.WaitUntil(IsMissingTold, 10.0), "the missing file was told");
	Runner.Command("sm_crypto_verify crypto-test/none.txt abc");
	Runner.Frames(1);
	Assert.ConsoleContains("\"abc\" is no SHA-256 digest");
}

public void Test_UnloadingAPluginDropsItsJobs() {
	CreateDirectory("crypto-test", 511);
	WriteTestFile("crypto-test/abc.txt", "abc");
	/* The job can only call back on a later frame, after the unload. */
	Runner.Command("sm_crypto_verify crypto-test/abc.txt %s", ABC_SHA256);
	Runner.Command("sm plugins unload verify-file");
	Assert.False(Runner.WaitUntil(IsMatchTold, 2.0), "the unloaded plugin got no callback");
}

public void Test_VerifyFileTellsAPathOutsideTheGameDirectory() {
	Runner.Command("sm_crypto_verify ../server.cfg %s", ABC_SHA256);
	Assert.True(Runner.WaitUntil(IsInvalidPathTold, 10.0), "the refused path was told");
}

/* ------------------------------------------------------------- signed-links */

/* The link the player was sent, after "Your stats: ". */
void GetLink(int client, char[] link, int maxlength) {
	for (int i = 0; i < Runner.ClientMessageCount(client); i++) {
		char message[512];
		Runner.GetClientMessage(client, i, message, sizeof(message));
		int at = StrContains(message, "Your stats: ");
		if (at != -1) {
			strcopy(link, maxlength, message[at + 12]);
			TrimString(link);
			return;
		}
	}
	Assert.Fail("the player got no link");
}

int ConnectPlayerWithLink(char[] query, int maxlength) {
	FindConVar("sm_signed_links_secret").SetString("a secret shared with the web site");
	int client = Runner.ConnectClient("Player", "STEAM_0:1:23");
	Runner.ClientCommand(client, "sm_mystats");
	char link[512];
	GetLink(client, link, sizeof(link));
	int queryAt = StrContains(link, "?");
	Assert.True(queryAt != -1, "the link %s has a query", link);
	strcopy(query, maxlength, link[queryAt + 1]);
	return client;
}

public void Test_SignedLinksAreValidOnlyUnchanged() {
	char query[512];
	ConnectPlayerWithLink(query, sizeof(query));
	Assert.StrContains(query, "steamid=76561197960265775&expires=");

	char output[512];
	Runner.CommandOutput(output, sizeof(output), "sm_signed_links_check \"%s\"", query);
	Assert.StrContains(output, "valid: steamid=76561197960265775");

	ReplaceString(query, sizeof(query), "76561197960265775", "76561197960265776");
	Runner.CommandOutput(output, sizeof(output), "sm_signed_links_check \"%s\"", query);
	Assert.StrContains(output, "invalid: wrong MAC");
}

public void Test_SignedLinksDependOnTheSecret() {
	char query[512];
	ConnectPlayerWithLink(query, sizeof(query));
	FindConVar("sm_signed_links_secret").SetString("another secret of the web site");
	char output[512];
	Runner.CommandOutput(output, sizeof(output), "sm_signed_links_check \"%s\"", query);
	Assert.StrContains(output, "invalid: wrong MAC");
}

public void Test_SignedLinksExpire() {
	char secret[] = "a secret shared with the web site";
	FindConVar("sm_signed_links_secret").SetString(secret);
	/* Signed right, but expired in 1970. */
	CryptoKey key = CryptoKey.FromString(secret);
	char mac[CRYPTO_MAX_HASH_HEX];
	key.Hmac(CryptoHash_SHA256, "steamid=76561197960265775&expires=1", mac, sizeof(mac));
	delete key;
	char output[512];
	Runner.CommandOutput(output, sizeof(output), "sm_signed_links_check \"steamid=76561197960265775&expires=1&sig=%s\"",
	                     mac);
	Assert.StrContains(output, "invalid: expired");
}

public void Test_SignedLinksRefuseASecretThatMayBeCut() {
	/* 255 characters fill the example's buffer of 256: the secret may have
	 * been cut, so no link is signed with it. */
	char secret[300];
	for (int i = 0; i < 255; i++) {
		secret[i] = 'a' + i % 26;
	}
	secret[255] = '\0';
	FindConVar("sm_signed_links_secret").SetString(secret);
	int client = Runner.ConnectClient("Player", "STEAM_0:1:23");
	Runner.ClientCommand(client, "sm_mystats");
	Assert.True(Runner.ClientMessageCount(client) > 0, "the player got an answer");
	char message[512];
	Runner.GetClientMessage(client, Runner.ClientMessageCount(client) - 1, message, sizeof(message));
	Assert.StrContains(message, "No link right now");
}

/* ------------------------------------------------------------- sealed-notes */

void ReadNotesFile(char[] content, int maxlength) {
	char path[PLATFORM_MAX_PATH];
	BuildPath(Path_SM, path, sizeof(path), "data/sealed-notes.txt");
	File file = OpenFile(path, "r");
	Assert.True(file != null, "the notes file exists");
	int read = file.ReadString(content, maxlength, -1);
	delete file;
	Assert.True(read > 0);
}

public void Test_SealedNotesKeepNotesUnreadable() {
	char output[512];
	Runner.CommandOutput(output, sizeof(output), "sm_note_set STEAM_0:1:23 joins late, ask before kicking");
	Assert.StrContains(output, "Note about STEAM_0:1:23 kept.");
	char content[2048];
	ReadNotesFile(content, sizeof(content));
	Assert.StrContains(content, "STEAM_0:1:23");
	Assert.False(StrContains(content, "kicking") != -1, "the file does not show the note");

	Runner.CommandOutput(output, sizeof(output), "sm_note_get STEAM_0:1:23");
	Assert.StrContains(output, "Note about STEAM_0:1:23: joins late, ask before kicking");
	Runner.CommandOutput(output, sizeof(output), "sm_note_get STEAM_0:1:24");
	Assert.StrContains(output, "No note about STEAM_0:1:24.");
}

public void Test_SealedNotesRefuseMovedNotes() {
	char output[512];
	Runner.CommandOutput(output, sizeof(output), "sm_note_set STEAM_0:1:23 trusted");
	char path[PLATFORM_MAX_PATH];
	BuildPath(Path_SM, path, sizeof(path), "data/sealed-notes.txt");
	KeyValues notes = new KeyValues("notes");
	notes.ImportFromFile(path);
	char note[512];
	notes.GetString("STEAM_0:1:23", note, sizeof(note));
	notes.SetString("STEAM_0:1:24", note);
	notes.ExportToFile(path);
	delete notes;
	Runner.CommandOutput(output, sizeof(output), "sm_note_get STEAM_0:1:24");
	Assert.StrContains(output, "was changed or is not this server's");
}

public void Test_SealedNotesKeepTheirKey() {
	char path[PLATFORM_MAX_PATH];
	BuildPath(Path_SM, path, sizeof(path), "data/sealed-notes.key");
	File file = OpenFile(path, "r");
	Assert.True(file != null, "the key file was written");
	char key[64];
	file.ReadLine(key, sizeof(key));
	delete file;
	TrimString(key);
	Assert.Equal(strlen(key), 44, "a 32-byte key in base64");
}

public void Test_SealedNotesKeepTheirKeyPrivate() {
	char path[PLATFORM_MAX_PATH];
	BuildPath(Path_SM, path, sizeof(path), "data/sealed-notes.key");
	int mode;
	Assert.True(GetFilePermissions(path, mode), "the key file was written");
	Assert.Equal(mode & 0x01FF, FPERM_U_READ | FPERM_U_WRITE, "only the server's user may read the key");
}
