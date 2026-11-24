# SMCrypto

SMCrypto is a SourceMod extension that gives plugins cryptography on
[Mbed TLS](https://www.trustedfirmware.org/projects/mbed-tls/): hashes, HMAC, HKDF, authenticated encryption, secure
random numbers and the encodings around them.

Typical uses: checking a downloaded file against its published SHA-256, signing links or webhook messages a web site
checks, keeping secrets in a config file or database encrypted, and making tokens and codes nobody can guess.

## Features

- Hashes: SHA-256, SHA-224, SHA-384, SHA-512, SHA3-224/256/384/512; SHA-1 and MD5 for formats that need them. Of
  buffers at once, of pieces with `CryptoDigest`, and of files on the extension's worker thread.
- HMAC (RFC 2104) with every hash, checked in constant time.
- HKDF (RFC 5869) to derive keys per purpose from one master key.
- Sealed messages: AES-256-GCM, ChaCha20-Poly1305 or AES-128-GCM with a fresh random nonce per message, bound to
  optional additional data, in one self-describing byte string that other languages read
  ([format](docs/formats.md)).
- Random bytes and unbiased random numbers from a CTR_DRBG seeded by the operating system.
- Hex, base64 and base64url, decoded strictly; comparison in constant time.
- Keys live in `CryptoKey` handles whose memory is wiped on delete.
- Linux and Windows, 32-bit and 64-bit servers, every game SourceMod supports. Mbed TLS is built in; nothing else
  needs to be installed.

## Requirements

- SourceMod 1.12 or newer.
- Linux with glibc 2.35 or newer (Ubuntu 22.04, Debian 12 and newer), or Windows. The Windows DLLs have so far been
  tested by their unit tests only, not on a Windows game server.

## Installation

The release archives (`sm-crypto-v<version>-linux.tar.gz`, `sm-crypto-v<version>-windows.zip`) hold the files below
`addons/sourcemod/`. Copy them into `addons/sourcemod/` of the game directory (for Team Fortress 2 `tf/`):

| File | Purpose |
|---|---|
| `extensions/smcrypto.ext.so`, `extensions/smcrypto.ext.dll` | The extension for 32-bit servers (Linux, Windows). |
| `extensions/x64/smcrypto.ext.so`, `extensions/x64/smcrypto.ext.dll` | The extension for 64-bit servers. |
| `scripting/include/smcrypto.inc` | The include file for compiling plugins. |
| `licenses/smcrypto/` | The license texts of SMCrypto and Mbed TLS. |

`sm exts list` in the server console then lists `SMCrypto (1.0.0)`. Plugins that include `smcrypto.inc` load the
extension themselves.

## Quick start

```sourcepawn
#include <sourcemod>
#include <smcrypto>

public void OnPluginStart() {
	// A digest of a string, as hex.
	char hex[CRYPTO_MAX_HASH_HEX];
	Crypto.Hash(CryptoHash_SHA256, "hello", hex, sizeof(hex));

	// A MAC only the key's holder can make, and its check.
	CryptoKey key = CryptoKey.FromString("a secret shared with the web site");
	char mac[CRYPTO_MAX_HASH_HEX];
	key.Hmac(CryptoHash_SHA256, "steamid=76561197960265775", mac, sizeof(mac));
	if (!key.HmacVerify(CryptoHash_SHA256, "steamid=76561197960265775", mac)) {
		LogError("forged");
	}
	delete key;

	// A secret encrypted at rest.
	CryptoKey storage = CryptoKey.Generate();
	char stored[256], opened[64];
	storage.Seal("rcon password", stored, sizeof(stored));        // base64 text
	storage.Open(stored, opened, sizeof(opened));                 // -1 when changed
	delete storage;
}
```

Wrong arguments (a buffer too small, an invalid enum value, a key of the wrong size) throw native errors; data that
can be wrong at run time (text that is not valid base64, a MAC that does not match, a message that does not open) is
told by the return value.

## Documentation

- [API reference](docs/api.md): conventions for bytes, encodings, buffers and errors, and every native.
- [Examples](docs/examples.md): hashing a buffer, checking a file, signed links with the web side in PHP and Python,
  notes encrypted at rest. The plugins are in [examples/](examples/) and run in the tests.
- [Formats](docs/formats.md): sealed messages and encodings, for reading them outside SourceMod.
- [Development](docs/development.md): building for Linux and Windows, the tests, the layout, updating Mbed TLS,
  releasing.

## AI disclosure

AI helped build this project. If that bothers you, no hard feelings - this project is just not for you.

## License

SMCrypto is licensed under the GNU General Public License version 3, with the same exceptions SourceMod grants; see
[LICENSE.txt](LICENSE.txt). Mbed TLS is used under the Apache License 2.0; its license text is installed into
`addons/sourcemod/licenses/smcrypto/`.
