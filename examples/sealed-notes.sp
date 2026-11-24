/**
 * Copyright 2026 ETF2L Contributors, Dave
 *
 * SMCrypto example: encrypting data at rest.
 *
 *   sm_note_set <steamid> <text>   keeps an admin note about a player
 *   sm_note_get <steamid>          prints it
 *
 * The notes live in data/sealed-notes.txt, each sealed with AES-256-GCM:
 * the file shows nothing of them, and a changed note does not open. Each
 * note is bound to its SteamID as additional data, so a note copied to
 * another player's entry does not open either.
 *
 * The key is made once and kept in data/sealed-notes.key as base64,
 * readable and writable by the server's user only; keep that file private
 * and out of backups the notes go to. The notes key is
 * derived from it with HKDF, so the same file could key other purposes
 * without one key serving two.
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <smcrypto>

public Plugin myinfo = {
	name = "SMCrypto example: sealed notes",
	author = "ETF2L Contributors, Dave",
	description = "Keeps admin notes encrypted with SMCrypto",
	version = "1.0.0",
	url = "https://github.com/etf2l/sm-crypto"
};

char g_keyPath[PLATFORM_MAX_PATH];
char g_notesPath[PLATFORM_MAX_PATH];
CryptoKey g_notesKey;

public void OnPluginStart() {
	BuildPath(Path_SM, g_keyPath, sizeof(g_keyPath), "data/sealed-notes.key");
	BuildPath(Path_SM, g_notesPath, sizeof(g_notesPath), "data/sealed-notes.txt");
	CryptoKey master = LoadOrCreateMasterKey();
	if (master == null) {
		SetFailState("Cannot read or write %s", g_keyPath);
	}
	g_notesKey = master.Derive("sealed-notes: notes v1");
	delete master;
	RegAdminCmd("sm_note_set", Command_Set, ADMFLAG_BAN, "sm_note_set <steamid> <text>: keeps a note");
	RegAdminCmd("sm_note_get", Command_Get, ADMFLAG_BAN, "sm_note_get <steamid>: prints a note");
}

CryptoKey LoadOrCreateMasterKey() {
	File file = OpenFile(g_keyPath, "r");
	char text[64];
	if (file != null) {
		file.ReadLine(text, sizeof(text));
		delete file;
		TrimString(text);
		return CryptoKey.Import(text);
	}
	CryptoKey key = CryptoKey.Generate();
	key.Export(text, sizeof(text));
	file = OpenFile(g_keyPath, "w");
	if (file == null) {
		delete key;
		return null;
	}
	// Private before the key is in it: a new file gets the process umask,
	// which usually lets every local user read it.
	if (!SetFilePermissions(g_keyPath, FPERM_U_READ | FPERM_U_WRITE)) {
		delete file;
		DeleteFile(g_keyPath);
		delete key;
		return null;
	}
	file.WriteLine(text);
	delete file;
	return key;
}

Action Command_Set(int client, int args) {
	char steamId[32], text[256];
	ReadSteamIdAndRest(steamId, sizeof(steamId), text, sizeof(text));
	if (steamId[0] == '\0' || text[0] == '\0') {
		ReplyToCommand(client, "Usage: sm_note_set <steamid> <text>");
		return Plugin_Handled;
	}

	// Crypto.SealedSize tells the buffer a sealed text of this length needs.
	char note[512];
	if (Crypto.SealedSize(strlen(text)) > sizeof(note)) {
		ReplyToCommand(client, "The note is too long.");
		return Plugin_Handled;
	}
	g_notesKey.Seal(text, note, sizeof(note), .aad = steamId);

	KeyValues notes = LoadNotes();
	notes.SetString(steamId, note);
	notes.ExportToFile(g_notesPath);
	delete notes;
	ReplyToCommand(client, "Note about %s kept.", steamId);
	return Plugin_Handled;
}

Action Command_Get(int client, int args) {
	char steamId[32], text[512];
	ReadSteamIdAndRest(steamId, sizeof(steamId), text, sizeof(text));
	KeyValues notes = LoadNotes();
	char note[512];
	notes.GetString(steamId, note, sizeof(note));
	delete notes;
	if (note[0] == '\0') {
		ReplyToCommand(client, "No note about %s.", steamId);
		return Plugin_Handled;
	}
	// A buffer as large as the sealed text always fits its plaintext.
	if (g_notesKey.Open(note, text, sizeof(text), .aad = steamId) == -1) {
		ReplyToCommand(client, "The note about %s was changed or is not this server's.", steamId);
		return Plugin_Handled;
	}
	ReplyToCommand(client, "Note about %s: %s", steamId, text);
	return Plugin_Handled;
}

// The engine splits arguments at ":", which SteamIDs hold, so the command
// line is split here instead.
void ReadSteamIdAndRest(char[] steamId, int steamIdLength, char[] rest, int restLength) {
	char line[512];
	GetCmdArgString(line, sizeof(line));
	int restAt = BreakString(line, steamId, steamIdLength);
	rest[0] = '\0';
	if (restAt != -1) {
		strcopy(rest, restLength, line[restAt]);
	}
}

KeyValues LoadNotes() {
	KeyValues notes = new KeyValues("notes");
	notes.ImportFromFile(g_notesPath);
	return notes;
}
