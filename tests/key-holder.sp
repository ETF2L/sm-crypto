/**
 * Copyright 2026 ETF2L Contributors, Dave
 *
 * A plugin that holds a key, for test_smcrypto.sp: other plugins must not
 * reach it, whatever they know of its handle.
 */
#pragma semicolon 1
#pragma newdecls required

#include <sourcemod>
#include <smcrypto>

public Plugin myinfo = {
	name = "SMCrypto test: key holder",
	author = "ETF2L Contributors, Dave",
	description = "Holds a key other plugins must not reach",
	version = "1.0.0",
	url = "https://github.com/etf2l/sm-crypto"
};

CryptoKey g_key;

public void OnPluginStart() {
	g_key = CryptoKey.FromString("a secret of the key holder");
}

public void OnPluginEnd() {
	delete g_key;
}
