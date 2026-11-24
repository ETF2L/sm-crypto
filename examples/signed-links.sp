/**
 * Copyright 2026 ETF2L Contributors, Dave
 *
 * SMCrypto example: signing with HMAC.
 *
 *   sm_mystats                      (players) prints a link to the player's
 *                                   stats page that is valid for an hour
 *   sm_signed_links_check <query>   (server) tells whether a link's query
 *                                   string is signed and not expired
 *
 * The web site and the server share a secret. The server signs the query
 * "steamid=<SteamID64>&expires=<unix time>" with HMAC-SHA256 and appends
 * "&sig=<hex>"; the site computes the same HMAC over the query before
 * "&sig=" and compares in constant time (docs/examples.md shows it in PHP
 * and Python). Nobody without the secret can make a valid link, and a
 * changed SteamID or expiry breaks the MAC.
 *
 * The secret is the cvar sm_signed_links_secret, protected so clients
 * cannot read it; set it in cfg/sourcemod/signed-links.cfg, e.g. to the
 * output of: openssl rand -base64 32
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <smcrypto>

#define LINK_LIFETIME 3600

public Plugin myinfo = {
	name = "SMCrypto example: signed links",
	author = "ETF2L Contributors, Dave",
	description = "Signs links to a web site with SMCrypto's HMAC",
	version = "1.0.0",
	url = "https://github.com/etf2l/sm-crypto"
};

ConVar g_secret;
ConVar g_baseUrl;
CryptoKey g_key;

public void OnPluginStart() {
	g_secret = CreateConVar("sm_signed_links_secret", "", "The secret shared with the web site, 16 to 254 characters",
	                        FCVAR_PROTECTED);
	g_baseUrl = CreateConVar("sm_signed_links_url", "https://stats.example.com/me?", "The stats page");
	g_secret.AddChangeHook(OnSecretChanged);
	AutoExecConfig(true, "signed-links");
	RegConsoleCmd("sm_mystats", Command_MyStats, "Prints a link to your stats page");
	RegServerCmd("sm_signed_links_check", Command_Check, "sm_signed_links_check <query>: checks a signed query");
}

public void OnConfigsExecuted() {
	LoadKey();
}

void OnSecretChanged(ConVar convar, const char[] oldValue, const char[] newValue) {
	LoadKey();
}

// A text secret is used as it is, the way a web site's HMAC function takes
// it; delete wipes the old key's memory. A secret that fills the buffer
// may have been cut, and a cut secret would sign every link wrong.
void LoadKey() {
	delete g_key;
	char secret[256];
	g_secret.GetString(secret, sizeof(secret));
	if (strlen(secret) < 16) {
		LogError("sm_signed_links_secret must be set to at least 16 characters");
		return;
	}
	if (strlen(secret) >= sizeof(secret) - 1) {
		LogError("sm_signed_links_secret must be shorter than %d characters", sizeof(secret) - 1);
		return;
	}
	g_key = CryptoKey.FromString(secret);
}

Action Command_MyStats(int client, int args) {
	char steamId[32];
	if (client == 0 || g_key == null || !GetClientAuthId(client, AuthId_SteamID64, steamId, sizeof(steamId))) {
		ReplyToCommand(client, "No link right now, try again later.");
		return Plugin_Handled;
	}
	char query[128];
	FormatEx(query, sizeof(query), "steamid=%s&expires=%d", steamId, GetTime() + LINK_LIFETIME);
	char mac[CRYPTO_MAX_HASH_HEX];
	g_key.Hmac(CryptoHash_SHA256, query, mac, sizeof(mac));
	char url[512];
	g_baseUrl.GetString(url, sizeof(url));
	Format(url, sizeof(url), "%s%s&sig=%s", url, query, mac);
	ReplyToCommand(client, "Your stats: %s", url);
	return Plugin_Handled;
}

// What the web site does, here for testing: split off "&sig=", check the
// MAC, then trust the fields.
Action Command_Check(int args) {
	char query[256];
	GetCmdArgString(query, sizeof(query));
	StripQuotes(query);
	int sigAt = StrContains(query, "&sig=");
	if (g_key == null || sigAt == -1) {
		PrintToServer("invalid: no MAC");
		return Plugin_Handled;
	}
	char mac[CRYPTO_MAX_HASH_HEX];
	strcopy(mac, sizeof(mac), query[sigAt + 5]);
	query[sigAt] = '\0';
	// HmacVerify compares in constant time; StrEqual would tell an attacker
	// by its timing how many leading digits of a forged MAC are right.
	if (!g_key.HmacVerify(CryptoHash_SHA256, query, mac)) {
		PrintToServer("invalid: wrong MAC");
		return Plugin_Handled;
	}
	int expiresAt = StrContains(query, "&expires=");
	if (expiresAt == -1 || StringToInt(query[expiresAt + 9]) < GetTime()) {
		PrintToServer("invalid: expired");
		return Plugin_Handled;
	}
	PrintToServer("valid: %s", query);
	return Plugin_Handled;
}
