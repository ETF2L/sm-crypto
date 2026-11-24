# API reference

`scripting/include/smcrypto.inc` documents every native and its arguments; this page describes the conventions they
share and how they fit together.

## Conventions

### Bytes in char arrays

Binary values (digests, keys, sealed messages, random bytes) travel in `char` arrays: a `char[]` holds any byte, NUL
included. Inputs come in two kinds:

- **Data** (`data`, `message`, `plaintext`, `info`, `salt`, `aad`): usually text. It is read up to its NUL unless its
  length is given; give the length for binary data, which may contain NULs.
- **Encoded values** (`mac`, `expected`, a sealed `message`, `CryptoKey.Import`'s `text`): read in a
  `CryptoEncoding`. With `CryptoEncoding_Raw` the length must be given, since a raw value may contain NULs.

Optional arguments can be named: `key.Seal(text, out, sizeof(out), .aad = steamId)`.

### Encodings

| `CryptoEncoding` | Writes | Decoding takes |
|---|---|---|
| `CryptoEncoding_Hex` | lowercase hex, 2 characters per byte | upper or lower case |
| `CryptoEncoding_Base64` | RFC 4648 base64 with `=` padding | exactly that, padding included |
| `CryptoEncoding_Base64Url` | RFC 4648 base64url without padding (URLs, file names, JWT) | exactly that, no padding |
| `CryptoEncoding_Raw` | the bytes themselves | the bytes, with their length |

Decoding is strict: no whitespace, no missing or extra padding, and the bits a last base64 character holds beyond the
value must be zero. Every value thus has one accepted text (apart from the case of hex digits), so a signed or stored
value cannot be altered by rewriting its text.

### Outputs and buffer sizes

Every native that writes a value takes an encoding and writes the encoded value **followed by a NUL**, so a buffer
needs one byte more than the value; this also holds for raw values, which makes a raw plaintext a usable string. The
return value is the number of bytes written without the NUL. A raw value may hold NULs of its own: use the returned
length, not `strlen`.

| Value | Buffer size |
|---|---|
| any value of `n` bytes | `Crypto.EncodedSize(n, encoding)` |
| a digest or MAC | `Crypto.EncodedSize(Crypto.HashSize(hash), encoding)`; `CRYPTO_MAX_HASH_HEX` (129) fits any hex digest |
| a sealed message | `Crypto.SealedSize(plaintextLength, encoding)` |
| an opened message | the size of the sealed text always fits |
| a key | `Crypto.EncodedSize(key.Length, encoding)` |

### Errors

- **A wrong argument throws a native error**: it is a bug in the plugin, and the native returns without doing
  anything. Wrong arguments are invalid enum values and handles (also a key or digest handle of another plugin), a
  hash or cipher this build does not support, negative lengths (other than -1 where it means up to the NUL), a
  `CryptoEncoding_Raw` value without its length, numbers out of their range (a key length, a number of random bytes,
  `min` above `max`), data that runs past the plugin's memory, a buffer too small for a value whose size is known in
  advance, a key of the wrong size for a cipher, and a finished `CryptoDigest`.
- **Data that can be wrong at run time is told by the return value or the callback** and never throws:
  `Crypto.Decode` and `CryptoKey.Open` return -1, `CryptoKey.Import` returns `null`, `HmacVerify` and `Verify` return
  false, and `Crypto.HashFile` reports a path outside the game directory as `CryptoError_InvalidPath`. This holds for
  invalid text in the input's encoding too, so untrusted input cannot make a plugin throw. One case does throw:
  `CryptoKey.Open` with a buffer too small for a message that opened; size the buffer by the rule above.
- **A failure of Mbed TLS itself** (out of memory) throws a native error that names the PSA function and status;
  memory that runs out in SMCrypto's own code throws the native error "SMCrypto ran out of memory".

Every span of plugin memory a native reads or writes is checked first: its first and last byte must be valid
addresses of the plugin, and it must lie either in data and heap or in the stack, never reach from the heap over the
free gap into the stack, where the VM keeps its frames. A `maxlength` larger than its array can still overwrite the
plugin's own variables next to it, as with SourceMod's own natives, but never the VM's frames or anything outside the
plugin. A native whose arguments do not lie on the plugin's stack (called by other code than the plugin's) cannot
tell where the stack begins and throws a native error instead of reading or writing plugin memory unchecked.

### Versions

Every native checks that it got all its arguments, so a plugin compiled against another `smcrypto.inc` fails with a
native error that says so instead of reading garbage. New natives are looked up with `GetFeatureStatus` as usual;
new hash and cipher values with `Crypto.IsHashSupported` and `Crypto.IsCipherSupported`, which are false for a
value this extension does not know or its build of Mbed TLS leaves out. Enum values never change.

## Crypto

| Native | Does |
|---|---|
| `Crypto.HashSize(hash)` | The digest's size in bytes. |
| `Crypto.IsHashSupported(hash)`, `Crypto.IsCipherSupported(cipher)` | Whether this extension has the value. |
| `Crypto.Hash(hash, data, output, maxlength, encoding = Hex, dataLength = -1)` | Hashes data. |
| `Crypto.HashFile(hash, path, callback, data = 0, encoding = Hex)` | Queues a file to be hashed; returns the job's id. |
| `Crypto.Cancel(job)` | Cancels a file job of the calling plugin. |
| `Crypto.EncodedSize(length, encoding)` | The buffer an encoded value of `length` bytes needs. |
| `Crypto.Encode(data, output, maxlength, encoding, dataLength = -1)` | Encodes bytes as text. |
| `Crypto.Decode(text, output, maxlength, encoding, textLength = -1)` | Decodes text; -1 when invalid or too long for output. |
| `Crypto.Random(output, maxlength, bytes, encoding = Hex)` | Writes 1 to 65536 random bytes. |
| `Crypto.RandomInt(min, max)` | A uniformly distributed number from `min` to `max`, both included. |
| `Crypto.Equal(a, b, length)` | Compares bytes in constant time. |
| `Crypto.SealedSize(plaintextLength, encoding = Base64, cipher = AES256GCM)` | The buffer `CryptoKey.Seal` needs. |
| `Crypto.ErrorString(error, buffer, maxlength)` | The name of a `CryptoError`, cut to fit the buffer. |

### Hash functions

| `CryptoHash` | Bytes | Use |
|---|---|---|
| `CryptoHash_SHA256` | 32 | The default for everything. |
| `CryptoHash_SHA224`, `_SHA384`, `_SHA512` | 28, 48, 64 | SHA-2 variants. |
| `CryptoHash_SHA3_224`, `_SHA3_256`, `_SHA3_384`, `_SHA3_512` | 28, 32, 48, 64 | SHA-3. |
| `CryptoHash_SHA1` | 20 | Old formats only: collisions are practical. |
| `CryptoHash_MD5` | 16 | Old formats only: collisions are trivial. |

SHA-1 and MD5 are there for protocols and file lists that fix their hash, which plugins could not speak otherwise. Never
compare files or authenticate anything with them: an attacker can make two different files with the same digest.

### Hashing files

`Crypto.HashFile` hashes on the extension's worker thread, so a large file does not stall the server. Jobs run one
after the other in the order they were queued, reading 64 KiB at a time. The callback runs on the main thread on a
later frame, never inside the call:

```sourcepawn
void OnHashed(int job, CryptoError error, const char[] path, const char[] digest, int digestLength, any data)
```

`job` is the id `HashFile` returned. `digest` is in the encoding asked for when the job was queued, empty unless
`error` is `CryptoError_None`. When the plugin unloads, its jobs are dropped without callbacks; when the extension
unloads, every job is.

`Crypto.Cancel(job)` drops a queued job or stops a running one at its next 64 KiB; the callback still runs, with
`CryptoError_Cancelled`, unless the job finished meanwhile. It returns false for an id that is no job of the calling
plugin, or no longer one; a job refused for its path counts as finished at once.

Paths are relative to the game directory, UTF-8, with `/` between parts. A path that is empty, has an empty, `.` or `..`
part, contains `\` or `:` (Windows separators, drive letters, `file://`), or is too long once joined to the game
directory is not hashed: its callback gets `CryptoError_InvalidPath` on a later frame, as any other job's would. A
plugin that hashes file names it read from a directory thus keeps going when a file has an odd name. Symbolic links
below the game directory are followed, and a link's target may lie outside it: the rule is on the path as written, so
whoever can write to the game directory can point a link anywhere. A directory, FIFO or other non-regular file is told
as `CryptoError_NotAFile` without being opened, and so is a DOS device name on Windows (`NUL`, `CON`, `COM1`, ... in any
directory, with any extension).

| `CryptoError` | Meaning |
|---|---|
| `CryptoError_None` | The file was hashed. |
| `CryptoError_NotFound` | Nothing is at the path. |
| `CryptoError_NotAFile` | The path is a directory or another non-regular file. |
| `CryptoError_Open` | The file cannot be opened, e.g. for lack of permission. |
| `CryptoError_Read` | Reading failed. |
| `CryptoError_Cancelled` | `Crypto.Cancel` cancelled the job. |
| `CryptoError_Internal` | Mbed TLS failed or memory ran out; the error log tells which. |
| `CryptoError_InvalidPath` | The path is not below the game directory, or too long. |

### Random numbers

`Crypto.Random` and `Crypto.RandomInt` draw from Mbed TLS's CTR_DRBG (AES-256), seeded from the operating system
(`getrandom` or `/dev/urandom` on Linux, `BCryptGenRandom` on Windows) and reseeded by Mbed TLS. Use them for keys,
tokens, link codes and anything an attacker must not guess; SourceMod's `GetRandomInt` is a fast generator for game
logic and is predictable. 16 random bytes make a token that cannot be guessed. `RandomInt` discards draws that would
make some numbers more likely, so every number in the range is equally likely.

## CryptoKey

A key is 1 to `CRYPTO_MAX_KEY_SIZE` (1024) bytes. Delete it when done; its memory is wiped. Only the plugin that owns
a key's handle can use it, and `CloneHandle` returns `null` for keys and digests, so no other plugin can take one,
even knowing its handle's value. To share a key between plugins, export it and import it.

| Native | Does |
|---|---|
| `CryptoKey.Generate(length = 32)` | A random key. |
| `CryptoKey.Import(text, encoding = Base64, textLength = -1)` | A key from encoded text; `null` when invalid. |
| `CryptoKey.FromString(secret)` | A key whose bytes are a string's, for text secrets. |
| `key.Length` | The key's size in bytes. |
| `key.Export(output, maxlength, encoding = Base64)` | Writes the key's bytes. |
| `key.Derive(info, length = 32, salt = "", hash = SHA256, infoLength = -1, saltLength = -1)` | HKDF: a new key. |
| `key.Hmac(hash, message, output, maxlength, encoding = Hex, messageLength = -1)` | The message's HMAC. |
| `key.HmacVerify(hash, message, mac, macEncoding = Hex, messageLength = -1, macLength = -1)` | Checks an HMAC. |
| `key.Seal(plaintext, output, maxlength, encoding = Base64, cipher = AES256GCM, aad = "", ...)` | Seals a message. |
| `key.Open(message, output, maxlength, encoding = Base64, aad = "", ...)` | Opens a sealed message; -1 when it does not. |

### Where keys come from

- **A key only the server uses** (encrypting data at rest): `CryptoKey.Generate()` once, `Export` it to a file only
  the server can read, `Import` it at start.
- **A secret shared with a web site** (signing links, webhooks): the site's secret as text with
  `CryptoKey.FromString`, or as base64 with `Import`. Prefer a long random secret (`openssl rand -base64 32`) to a
  passphrase; a passphrase is no key.
- **One key per purpose**: derive keys from one master key with `Derive`, with an `info` that names the purpose and a
  version (`"myplugin tokens v1"`). Never use one key both for HMAC and for sealing.

Do not keep a secret in a cvar without `FCVAR_PROTECTED`, and never print one.

### HMAC

`Hmac` makes a MAC that only a holder of the key can make: it proves that a message comes from a key holder and was
not changed. `HmacVerify` checks one in constant time. Always check MACs with it (or with `Crypto.Equal` on the raw
bytes), never with `StrEqual`, whose run time tells an attacker how many leading characters of a forged MAC are
right. A MAC proves nothing about when it was made: put an expiry or a counter into the message to stop replays.

### Sealed messages

`Seal` encrypts and authenticates a plaintext into a sealed message: only the key opens it, and any change to it is
noticed. Each call draws a new random nonce, so the same plaintext seals to a different message every time. `aad`
(additional data) binds the message to bytes it does not hold, for example the SteamID a note is about: `Open` must
be given the same `aad`, so a message copied to another player's entry does not open.

| `CryptoCipher` | Key | Note |
|---|---|---|
| `CryptoCipher_AES256GCM` | 32 bytes | The default. |
| `CryptoCipher_ChaCha20Poly1305` | 32 bytes | RFC 8439. |
| `CryptoCipher_AES128GCM` | 16 bytes | |

`Open` reads the cipher from the message; it returns -1, writing nothing, when the message is not valid in its
encoding, was changed, was sealed with another key or `aad`, or is no sealed message at all. The reasons are not told
apart. Seal at most 2^32 messages with one key (random 96-bit nonces); derive a new key per purpose or period beyond
that. The format is in [formats.md](formats.md).

## CryptoDigest

A hash or HMAC fed in pieces, for a value put together from several strings.

| Native | Does |
|---|---|
| `new CryptoDigest(hash)` | Starts a hash. |
| `CryptoDigest.Hmac(hash, key)` | Starts an HMAC; the digest keeps its own copy of the key. |
| `digest.Hash`, `digest.IsFinished` | The hash function; whether it was ended (or an `Update` failed). |
| `digest.Update(data, dataLength = -1)` | Adds bytes. |
| `digest.Final(output, maxlength, encoding = Hex)` | Ends it and writes the digest. |
| `digest.Verify(expected, encoding = Hex, expectedLength = -1)` | Ends it and compares in constant time. |

After `Final` or `Verify` only `Hash` and `IsFinished` may be used; delete the handle. `Verify` ends the digest also
when `expected` is not valid text in its encoding. A buffer too small for `Final`
throws before the digest ends, so it can be called again.

## Threads and lifetime

All natives run on the main thread and finish at once. `HashFile` returns at once too, but its file is hashed on the
extension's one worker thread. Keys, digests and the random generator are never used off the main thread.

Keys and digests live until the plugin deletes them or unloads; SourceMod then frees their handles, and a key's memory
is wiped. Unloading the extension frees every key and digest.
