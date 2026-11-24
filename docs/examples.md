# Examples

Each example is a complete plugin in [examples/](../examples/); `tests/test_examples.sp` runs them through their
commands, so they are known to work. The snippets here show the parts that matter.

- [Hashing a buffer](#hashing-a-buffer)
- [Hashing a file and checking it](#hashing-a-file-and-checking-it)
- [Signing with HMAC](#signing-with-hmac): signed links, checked by a web site
- [Encrypting data at rest](#encrypting-data-at-rest): sealed notes
- [Smaller recipes](#smaller-recipes): tokens, codes, binary data, webhooks

## Hashing a buffer

[examples/hash-text.sp](../examples/hash-text.sp): `sm_crypto_hash <text>`.

```sourcepawn
char sha256[CRYPTO_MAX_HASH_HEX];
Crypto.Hash(CryptoHash_SHA256, text, sha256, sizeof(sha256));
```

`CRYPTO_MAX_HASH_HEX` fits the hex digest of every hash. For a value made of several pieces, a `CryptoDigest` avoids
copying them into one buffer first; here it makes a short id in base64url:

```sourcepawn
CryptoDigest digest = new CryptoDigest(CryptoHash_SHA256);
digest.Update(length);
digest.Update(":");
digest.Update(text);
char id[64];
digest.Final(id, sizeof(id), CryptoEncoding_Base64Url);
delete digest;
id[16] = '\0';  // 96 bits are plenty for an id
```

Binary data is passed with its length: `Crypto.Hash(CryptoHash_SHA256, bytes, out, sizeof(out), .dataLength = n)`.

## Hashing a file and checking it

[examples/verify-file.sp](../examples/verify-file.sp): `sm_crypto_verify <path> <sha256>` (admins with the config
flag), for example to check a downloaded plugin against the digest its release lists.

`Crypto.HashFile` hashes on the extension's worker thread and calls back on a later frame. Whatever the callback needs
travels in `data`, here a `DataPack` with the user id of whoever ran the command (the client may leave meanwhile),
the reply source and the expected digest:

```sourcepawn
// Decoding refuses a digest that is no hex or has the wrong length up front.
char expectedBytes[CRYPTO_MAX_HASH_SIZE + 1];
if (Crypto.Decode(expected, expectedBytes, sizeof(expectedBytes), CryptoEncoding_Hex)
        != Crypto.HashSize(CryptoHash_SHA256)) {
	ReplyToCommand(client, "\"%s\" is no SHA-256 digest", expected);
	return Plugin_Handled;
}
DataPack pack = new DataPack();
pack.WriteCell(client == 0 ? 0 : GetClientUserId(client));
pack.WriteCell(GetCmdReplySource());
pack.WriteString(expected);
Crypto.HashFile(CryptoHash_SHA256, path, OnFileHashed, pack, CryptoEncoding_Raw);
```

```sourcepawn
void OnFileHashed(int job, CryptoError error, const char[] path, const char[] digest, int digestLength,
                  DataPack pack) {
	// ... read the pack, find the client ...
	if (error != CryptoError_None) {
		char name[32];
		Crypto.ErrorString(error, name, sizeof(name));
		ReplyToCommand(client, "%s cannot be hashed: %s", path, name);
		return;
	}
	bool isMatch = Crypto.Equal(digest, expectedBytes, digestLength);
}
```

A path outside the game directory is not hashed; the callback gets `CryptoError_InvalidPath`, so a path typed by an
admin or read from a directory listing cannot make the command throw.

## Signing with HMAC

[examples/signed-links.sp](../examples/signed-links.sp): `sm_mystats` gives a player a link to their page on a web
site, valid for an hour, that nobody can forge or change.

The server and the site share a secret. The server signs the query with HMAC-SHA256 and appends the MAC:

```sourcepawn
g_key = CryptoKey.FromString(secret);   // in OnConfigsExecuted, from a protected cvar
...
char query[128];
FormatEx(query, sizeof(query), "steamid=%s&expires=%d", steamId, GetTime() + 3600);
char mac[CRYPTO_MAX_HASH_HEX];
g_key.Hmac(CryptoHash_SHA256, query, mac, sizeof(mac));
// https://stats.example.com/me?steamid=7656...&expires=1764...&sig=3f2a...
```

The site computes the HMAC over everything before `&sig=`, compares in constant time, and only then reads the fields.

PHP:

```php
$query = $_SERVER['QUERY_STRING'];
$at = strrpos($query, '&sig=');
if ($at === false) {
    http_response_code(403);
    exit;
}
$signed = substr($query, 0, $at);
$expected = hash_hmac('sha256', $signed, getenv('STATS_LINK_SECRET'));
if (!hash_equals($expected, substr($query, $at + 5))) {
    http_response_code(403);
    exit;
}
parse_str($signed, $fields);
if ((int)$fields['expires'] < time()) {
    http_response_code(403);
    exit;
}
// $fields['steamid'] is genuine
```

Python:

```python
import hashlib, hmac, time
from urllib.parse import parse_qs

def check_link(query: str, secret: bytes) -> dict | None:
    signed, separator, mac = query.rpartition("&sig=")
    expected = hmac.new(secret, signed.encode(), hashlib.sha256).hexdigest()
    if not separator or not hmac.compare_digest(expected, mac):
        return None
    fields = {name: values[0] for name, values in parse_qs(signed).items()}
    return fields if int(fields["expires"]) >= time.time() else None
```

On the server, `key.HmacVerify` does the same check (`sm_signed_links_check` in the example). Keep the expiry inside
the signed part: a MAC alone cannot tell an old link from a new one.

The secret lives in the cvar `sm_signed_links_secret`, created with `FCVAR_PROTECTED` so clients cannot query it.
Make it long and random: `openssl rand -base64 32`. The example refuses a secret shorter than 16 characters. It reads
the secret into a buffer of 256 bytes and also refuses one of 255 characters or more, which may have been cut: a cut
secret would sign every link with another key than the site's.

## Encrypting data at rest

[examples/sealed-notes.sp](../examples/sealed-notes.sp): `sm_note_set <steamid> <text>` and `sm_note_get <steamid>`
(admins with the ban flag) keep admin notes in a KeyValues file, `addons/sourcemod/data/sealed-notes.txt`, each sealed
with AES-256-GCM.

The master key is made once and kept in its own file, `addons/sourcemod/data/sealed-notes.key`, as base64, readable
and writable by the server's user only; the key the notes use is derived from it for this one purpose:

```sourcepawn
CryptoKey LoadOrCreateMasterKey() {
	char text[64];
	File file = OpenFile(g_keyPath, "r");
	if (file != null) {
		file.ReadLine(text, sizeof(text));
		delete file;
		TrimString(text);
		return CryptoKey.Import(text);          // null when the file was damaged
	}
	CryptoKey key = CryptoKey.Generate();
	key.Export(text, sizeof(text));             // base64
	file = OpenFile(g_keyPath, "w");
	// ... check file ...
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

g_notesKey = master.Derive("sealed-notes: notes v1");
delete master;
```

Each note is bound to its SteamID as additional data, so a note copied to another player's entry does not open:

```sourcepawn
char note[512];
if (Crypto.SealedSize(strlen(text)) > sizeof(note)) {
	ReplyToCommand(client, "The note is too long.");
	return Plugin_Handled;
}
g_notesKey.Seal(text, note, sizeof(note), .aad = steamId);
...
if (g_notesKey.Open(note, text, sizeof(text), .aad = steamId) == -1) {
	ReplyToCommand(client, "The note about %s was changed or is not this server's.", steamId);
}
```

Keep the key file out of the backups the notes go to: whoever has both reads the notes. A web panel reads the notes
with the same master key and the same derivation, as [formats.md](formats.md) shows in Python.

## Smaller recipes

A token for a link code or a session, unguessable and safe in URLs:

```sourcepawn
char token[32];
Crypto.Random(token, sizeof(token), 16, CryptoEncoding_Base64Url);   // 22 characters
```

A six-digit code a player types into Discord or a web form:

```sourcepawn
int code = Crypto.RandomInt(0, 999999);
PrintToChat(client, "Your code: %06d", code);
```

A webhook from a web site, signed with a shared secret in a header (GitHub style, `sha256=<hex>`):

```sourcepawn
bool IsGenuineWebhook(CryptoKey key, const char[] body, int bodyLength, const char[] header) {
	return StrContains(header, "sha256=") == 0
	    && key.HmacVerify(CryptoHash_SHA256, body, header[7], .messageLength = bodyLength);
}
```

Binary data round trip: raw values come with their length and may hold NULs.

```sourcepawn
char raw[CRYPTO_MAX_HASH_SIZE + 1], text[CRYPTO_MAX_HASH_HEX];
int length = Crypto.Hash(CryptoHash_SHA512, "abc", raw, sizeof(raw), CryptoEncoding_Raw);   // 64
Crypto.Encode(raw, text, sizeof(text), CryptoEncoding_Hex, length);
```
