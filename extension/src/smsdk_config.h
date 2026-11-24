/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The extension's description for SourceMod's smsdk_ext. */
#ifndef _INCLUDE_SOURCEMOD_EXTENSION_CONFIG_H_
#define _INCLUDE_SOURCEMOD_EXTENSION_CONFIG_H_

#include "version.h"

#define SMEXT_CONF_NAME        "SMCrypto"
#define SMEXT_CONF_DESCRIPTION "Hashes, HMAC, HKDF, authenticated encryption and random numbers, on Mbed TLS"
#define SMEXT_CONF_VERSION     SMCRYPTO_VERSION_STRING
#define SMEXT_CONF_AUTHOR      "ETF2L Contributors, Dave"
#define SMEXT_CONF_URL         "https://github.com/etf2l/sm-crypto"
#define SMEXT_CONF_LOGTAG      "SMCRYPTO"
#define SMEXT_CONF_LICENSE     "GPL"
#define SMEXT_CONF_DATESTRING  __DATE__

#define SMEXT_LINK(name) SDKExtension *g_pExtensionIface = name;

#define SMEXT_ENABLE_HANDLESYS
#define SMEXT_ENABLE_PLUGINSYS

#endif // _INCLUDE_SOURCEMOD_EXTENSION_CONFIG_H_
