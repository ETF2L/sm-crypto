/**
 * Copyright 2026 ETF2L Contributors, Dave
 *
 * SMCrypto: cryptography for SourceMod plugins, on Mbed TLS.
 *
 *   Crypto        hashes (SHA-2, SHA-3; SHA-1 and MD5 for old formats),
 *                 files hashed on the worker thread, hex and base64, random
 *                 bytes and numbers, comparison in constant time
 *   CryptoKey     a secret key: HMAC, HKDF and sealed messages
 *                 (AES-GCM, ChaCha20-Poly1305)
 *   CryptoDigest  a hash or HMAC fed in pieces
 *
 * Bytes. Binary values travel in char arrays: a char[] holds any byte,
 * NUL included. Inputs that are usually text ("data", "message",
 * "plaintext", "info", ...) are read up to their NUL unless their length
 * is given. Inputs that are cryptographic values (a MAC, a sealed message)
 * are read in a CryptoEncoding; with CryptoEncoding_Raw their length must
 * be given.
 *
 * Outputs. Every native that writes a value takes a CryptoEncoding and
 * writes the encoded value followed by a NUL, so the buffer needs one byte
 * more than the value: Crypto.EncodedSize() tells how many. Such a native
 * returns the number of bytes written without the NUL. A Raw value may
 * hold NULs of its own; use the returned length, not strlen().
 *
 * Versions. Every native checks that it got all its arguments, so a plugin
 * compiled against another smcrypto.inc fails with a clear native error
 * instead of misreading its arguments; use Crypto.IsHashSupported and
 * Crypto.IsCipherSupported before using a value added later.
 *
 * Errors. A wrong argument is a bug in the plugin and throws a native
 * error: an invalid enum value, handle or length, a hash or cipher this
 * build does not support, a key of the wrong size, a buffer too small for
 * a value whose size is known in advance. Data that
 * can be wrong at run time is told by the return value or the callback:
 * text that is not valid in its encoding, a MAC that does not match, a
 * sealed message that does not open, a path outside the game directory.
 *
 * Secrets. CryptoKey handles keep their bytes in memory that is wiped when
 * the handle is deleted; copies a plugin makes into its own arrays are not
 * wiped.
 *
 * Documentation: https://github.com/etf2l/sm-crypto
 */

#if defined _smcrypto_included
#endinput
#endif
#define _smcrypto_included

/** The largest digest in bytes (SHA-512, SHA3-512). */
#define CRYPTO_MAX_HASH_SIZE 64

/** A buffer that holds any digest as hex, with its NUL. */
#define CRYPTO_MAX_HASH_HEX 129

/** The size of the keys AES-256-GCM and ChaCha20-Poly1305 use. */
#define CRYPTO_KEY_SIZE 32

/** The largest key in bytes; keys are 1 to this many bytes long. */
#define CRYPTO_MAX_KEY_SIZE 1024

/**
 * What sealing with each of the ciphers below adds to the plaintext's bytes:
 * format, nonce and tag. A later cipher may add more; Crypto.SealedSize
 * tells it for any.
 */
#define CRYPTO_SEAL_OVERHEAD 29

/** Hash functions. The values never change. */
enum CryptoHash {
	CryptoHash_SHA256 = 0,   /**< SHA-256, 32 bytes: the default choice */
	CryptoHash_SHA224 = 1,   /**< SHA-224, 28 bytes */
	CryptoHash_SHA384 = 2,   /**< SHA-384, 48 bytes */
	CryptoHash_SHA512 = 3,   /**< SHA-512, 64 bytes */
	CryptoHash_SHA3_224 = 4, /**< SHA3-224, 28 bytes */
	CryptoHash_SHA3_256 = 5, /**< SHA3-256, 32 bytes */
	CryptoHash_SHA3_384 = 6, /**< SHA3-384, 48 bytes */
	CryptoHash_SHA3_512 = 7, /**< SHA3-512, 64 bytes */
	CryptoHash_SHA1 = 8,     /**< SHA-1, 20 bytes. Collisions are practical: only for formats that need it */
	CryptoHash_MD5 = 9       /**< MD5, 16 bytes. Collisions are trivial: only for formats that need it */
};

/** Text forms of binary values. The values never change. */
enum CryptoEncoding {
	CryptoEncoding_Hex = 0,       /**< Lowercase hex digits; decoding takes either case */
	CryptoEncoding_Base64 = 1,    /**< RFC 4648 base64 with "=" padding */
	CryptoEncoding_Base64Url = 2, /**< RFC 4648 base64url without padding, safe in URLs and file names */
	CryptoEncoding_Raw = 3        /**< The bytes themselves */
};

/** Ciphers of sealed messages. The values never change. */
enum CryptoCipher {
	CryptoCipher_AES256GCM = 0,        /**< AES-256 in GCM mode, 32-byte key: the default choice */
	CryptoCipher_ChaCha20Poly1305 = 1, /**< ChaCha20-Poly1305 (RFC 8439), 32-byte key */
	CryptoCipher_AES128GCM = 2         /**< AES-128 in GCM mode, 16-byte key */
};

/** How hashing a file ended. The values never change. */
enum CryptoError {
	CryptoError_None = 0,       /**< Success */
	CryptoError_NotFound = 1,   /**< Nothing is at the path */
	CryptoError_NotAFile = 2,   /**< The path is a directory or another non-regular file */
	CryptoError_Open = 3,       /**< The file cannot be opened, e.g. for lack of permission */
	CryptoError_Read = 4,       /**< Reading the file failed */
	CryptoError_Cancelled = 5,  /**< Crypto.Cancel cancelled the job */
	CryptoError_Internal = 6,   /**< The crypto library failed or memory ran out; the error log tells which */
	CryptoError_InvalidPath = 7 /**< The path is not below the game directory (see Crypto.HashFile) or too long */
};

/**
 * Called on the main thread, on a later frame, when a file was hashed.
 *
 * @param job           The job's id, as Crypto.HashFile returned it.
 * @param error         How hashing ended.
 * @param path          The path as it was passed to Crypto.HashFile.
 * @param digest        The digest in the encoding that was asked for;
 *                      empty unless error is CryptoError_None.
 * @param digestLength  The digest's length in that encoding, 0 on failure.
 * @param data          The value passed to Crypto.HashFile.
 */
typedef CryptoHashFileCallback = function void (int job, CryptoError error, const char[] path,
                                                const char[] digest, int digestLength, any data);

/**
 * Hashing, encodings, randomness and comparison. Everything except
 * HashFile works at once.
 */
methodmap Crypto {
	/**
	 * Returns the size of a digest in bytes, e.g. 32 for SHA-256.
	 *
	 * @error  An invalid hash.
	 */
	public static native int HashSize(CryptoHash hash);

	/**
	 * Tells whether this extension has a hash function: a value added in a
	 * later smcrypto.inc, or one a build of the library leaves out, is not.
	 * Natives throw a native error for an unsupported hash.
	 *
	 * @return  true when the hash can be used.
	 */
	public static native bool IsHashSupported(CryptoHash hash);

	/**
	 * Tells whether this extension has a cipher, as IsHashSupported does for
	 * hashes.
	 *
	 * @return  true when the cipher can be used.
	 */
	public static native bool IsCipherSupported(CryptoCipher cipher);

	/**
	 * Hashes data.
	 *
	 * @param hash        The hash function.
	 * @param data        The bytes to hash.
	 * @param output      Receives the digest.
	 * @param maxlength   The size of output: Crypto.EncodedSize(Crypto.HashSize(hash), encoding)
	 *                    or more (CRYPTO_MAX_HASH_HEX fits any hex digest).
	 * @param encoding    How the digest is written.
	 * @param dataLength  The number of bytes of data, or -1 to hash up to its NUL.
	 * @return            The bytes written, without the NUL.
	 * @error             An invalid argument or a buffer too small.
	 */
	public static native int Hash(CryptoHash hash, const char[] data, char[] output, int maxlength,
	                              CryptoEncoding encoding = CryptoEncoding_Hex, int dataLength = -1);

	/**
	 * Queues a file to be hashed on the worker thread. Files are hashed one
	 * after the other in the order they were queued, and the callback runs
	 * on a later frame. When the plugin unloads, its jobs are dropped
	 * without callbacks.
	 *
	 * @param hash      The hash function.
	 * @param path      The file, relative to the game directory (tf/), with
	 *                  "/" between parts, e.g. "addons/sourcemod/plugins/x.smx".
	 *                  A path that is empty, has an empty, "." or ".." part,
	 *                  contains "\" or ":", or is too long once joined to
	 *                  the game directory is not hashed: the callback gets
	 *                  CryptoError_InvalidPath. Symbolic links are followed;
	 *                  a link's target may lie outside the game directory.
	 * @param callback  Called when the file was hashed or hashing failed.
	 * @param data      Passed to the callback.
	 * @param encoding  How the digest is passed to the callback.
	 * @return          The job's id, for Crypto.Cancel; always above 0.
	 * @error           An invalid hash, callback or encoding.
	 */
	public static native int HashFile(CryptoHash hash, const char[] path, CryptoHashFileCallback callback,
	                                  any data = 0, CryptoEncoding encoding = CryptoEncoding_Hex);

	/**
	 * Cancels a job of this plugin. A queued job is dropped, a running one
	 * stops at its next 64 KiB; either way its callback still runs on a
	 * later frame, with CryptoError_Cancelled, unless the job finished
	 * meanwhile. A job refused for its path counts as finished at once.
	 *
	 * @param job  The id Crypto.HashFile returned.
	 * @return     false when the plugin has no such job (any more).
	 */
	public static native bool Cancel(int job);

	/**
	 * Returns the buffer size an encoded value needs, its NUL included.
	 *
	 * @param length    The value's length in bytes, 0 or more.
	 * @param encoding  The encoding.
	 * @return          The size in bytes.
	 * @error           A negative length, an invalid encoding, or a size
	 *                  above 2^31 - 1.
	 */
	public static native int EncodedSize(int length, CryptoEncoding encoding);

	/**
	 * Encodes bytes as text.
	 *
	 * @param data        The bytes to encode.
	 * @param output      Receives the text.
	 * @param maxlength   The size of output: Crypto.EncodedSize(dataLength, encoding) or more.
	 * @param encoding    The text's encoding.
	 * @param dataLength  The number of bytes of data, or -1 for up to its NUL.
	 * @return            The bytes written, without the NUL.
	 * @error             An invalid argument or a buffer too small.
	 */
	public static native int Encode(const char[] data, char[] output, int maxlength, CryptoEncoding encoding,
	                                int dataLength = -1);

	/**
	 * Decodes text into bytes. Decoding is strict: a base64 text must have
	 * its padding and base64url none, no whitespace is taken, and the bits a
	 * last character holds beyond the value must be zero, so each value has
	 * exactly one text (hex digits may be upper or lower case).
	 *
	 * @param text        The text to decode.
	 * @param output      Receives the bytes, followed by a NUL.
	 * @param maxlength   The size of output, 1 or more.
	 * @param encoding    The text's encoding.
	 * @param textLength  The text's length, or -1 for up to its NUL.
	 * @return            The bytes written, without the NUL; -1 when text is
	 *                    not valid or its bytes and the NUL do not fit into
	 *                    output, since text may come from anyone. Nothing is
	 *                    written then.
	 * @error             An invalid argument.
	 */
	public static native int Decode(const char[] text, char[] output, int maxlength, CryptoEncoding encoding,
	                                int textLength = -1);

	/**
	 * Writes random bytes from a CTR_DRBG seeded from the operating system:
	 * for keys, tokens, codes and nonces.
	 *
	 * @param output     Receives the bytes.
	 * @param maxlength  The size of output: Crypto.EncodedSize(bytes, encoding) or more.
	 * @param bytes      How many random bytes, 1 to 65536; 16 make a token that cannot be guessed.
	 * @param encoding   How they are written.
	 * @return           The bytes written, without the NUL.
	 * @error            An invalid argument or a buffer too small.
	 */
	public static native int Random(char[] output, int maxlength, int bytes,
	                                CryptoEncoding encoding = CryptoEncoding_Hex);

	/**
	 * Returns a random number from min to max, both included, each equally
	 * likely, from the same generator as Crypto.Random.
	 *
	 * @error  min greater than max.
	 */
	public static native int RandomInt(int min, int max);

	/**
	 * Compares two byte strings in time that does not depend on where they
	 * differ, so an attacker cannot learn a secret by timing the comparison.
	 *
	 * @param a       The first bytes.
	 * @param b       The second bytes.
	 * @param length  How many bytes of each to compare, 0 or more.
	 * @return        true when the bytes are equal.
	 * @error         A negative length.
	 */
	public static native bool Equal(const char[] a, const char[] b, int length);

	/**
	 * Returns the buffer size CryptoKey.Seal needs for a plaintext, the NUL
	 * included.
	 *
	 * @param plaintextLength  The plaintext's length in bytes, 0 or more.
	 * @param encoding         The encoding the sealed message is written in.
	 * @param cipher           The cipher it is sealed with.
	 * @error                  An invalid argument.
	 */
	public static native int SealedSize(int plaintextLength, CryptoEncoding encoding = CryptoEncoding_Base64,
	                                    CryptoCipher cipher = CryptoCipher_AES256GCM);

	/**
	 * Writes the name of a CryptoError, e.g. "CryptoError_NotFound", cut to
	 * fit the buffer.
	 *
	 * @return  The bytes written, without the NUL.
	 * @error   An invalid value or a buffer size below 1.
	 */
	public static native int ErrorString(CryptoError error, char[] buffer, int maxlength);
}

/**
 * A secret key of 1 to CRYPTO_MAX_KEY_SIZE bytes. One key serves one
 * purpose: derive a key per purpose with Derive instead of using one key
 * for both HMAC and sealing. Delete it when done; its memory is wiped.
 * Only the plugin that made a key can use it, and CloneHandle returns null
 * for it, so no other plugin can take it; to share a key, export it.
 */
methodmap CryptoKey < Handle {
	/**
	 * Creates a random key.
	 *
	 * @param length  The key's length in bytes; 32 fits every cipher but
	 *                CryptoCipher_AES128GCM (16).
	 * @return        The key.
	 * @error         A length outside 1 to CRYPTO_MAX_KEY_SIZE.
	 */
	public static native CryptoKey Generate(int length = CRYPTO_KEY_SIZE);

	/**
	 * Creates a key from encoded text, e.g. one stored in a config file
	 * after CryptoKey.Export.
	 *
	 * @param text       The key's bytes in encoding.
	 * @param encoding   The text's encoding.
	 * @param textLength The text's length, or -1 for up to its NUL; needed
	 *                   for CryptoEncoding_Raw.
	 * @return           The key, or null when text is not valid in encoding
	 *                   or its key is not 1 to CRYPTO_MAX_KEY_SIZE bytes long.
	 * @error            An invalid encoding or length.
	 */
	public static native CryptoKey Import(const char[] text, CryptoEncoding encoding = CryptoEncoding_Base64,
	                                      int textLength = -1);

	/**
	 * Creates a key whose bytes are a string's, for secrets that are text
	 * such as a webhook secret shared with a web site. A passphrase is no
	 * random key: prefer Generate or a long random secret.
	 *
	 * @param secret  The secret, 1 to CRYPTO_MAX_KEY_SIZE bytes up to its NUL.
	 * @return        The key.
	 * @error         An empty or too long secret.
	 */
	public static native CryptoKey FromString(const char[] secret);

	/** The key's length in bytes. */
	property int Length {
		public native get();
	}

	/**
	 * Writes the key's bytes, e.g. to store a generated key.
	 *
	 * @param output     Receives the key.
	 * @param maxlength  The size of output: Crypto.EncodedSize(key.Length, encoding) or more.
	 * @param encoding   How the key is written.
	 * @return           The bytes written, without the NUL.
	 * @error            An invalid argument or a buffer too small.
	 */
	public native int Export(char[] output, int maxlength, CryptoEncoding encoding = CryptoEncoding_Base64);

	/**
	 * Derives a new key from this one with HKDF (RFC 5869), e.g. one key per
	 * purpose from one master key. The same key, info, salt and hash always
	 * derive the same key.
	 *
	 * @param info        What the key is for, e.g. "myplugin tokens v1".
	 * @param length      The new key's length in bytes, 1 to CRYPTO_MAX_KEY_SIZE
	 *                    and at most 255 digests of hash.
	 * @param salt        Optional salt; "" for none.
	 * @param hash        The hash HKDF runs on.
	 * @param infoLength  The length of info, or -1 for up to its NUL.
	 * @param saltLength  The length of salt, or -1 for up to its NUL.
	 * @return            The new key.
	 * @error             An invalid argument.
	 */
	public native CryptoKey Derive(const char[] info, int length = CRYPTO_KEY_SIZE, const char[] salt = "",
	                               CryptoHash hash = CryptoHash_SHA256, int infoLength = -1, int saltLength = -1);

	/**
	 * Signs a message with HMAC (RFC 2104): only a holder of the key can make
	 * the same MAC, so it proves the message came from a key holder and was
	 * not changed.
	 *
	 * @param hash           The hash HMAC runs on.
	 * @param message        The message.
	 * @param output         Receives the MAC, as long as a digest of hash.
	 * @param maxlength      The size of output: Crypto.EncodedSize(Crypto.HashSize(hash), encoding) or more.
	 * @param encoding       How the MAC is written.
	 * @param messageLength  The message's length, or -1 for up to its NUL.
	 * @return               The bytes written, without the NUL.
	 * @error                An invalid argument or a buffer too small.
	 */
	public native int Hmac(CryptoHash hash, const char[] message, char[] output, int maxlength,
	                       CryptoEncoding encoding = CryptoEncoding_Hex, int messageLength = -1);

	/**
	 * Checks a message's HMAC in constant time. Always check MACs with this,
	 * not with StrEqual, which tells by its timing how much of a MAC is right.
	 *
	 * @param hash           The hash HMAC runs on.
	 * @param message        The message.
	 * @param mac            The MAC to check, in macEncoding.
	 * @param macEncoding    The MAC's encoding.
	 * @param messageLength  The message's length, or -1 for up to its NUL.
	 * @param macLength      The MAC's length, or -1 for up to its NUL; needed
	 *                       for CryptoEncoding_Raw.
	 * @return               true when mac is the message's HMAC; false when
	 *                       it is not, also when it is not valid in its
	 *                       encoding or has another length.
	 * @error                An invalid argument.
	 */
	public native bool HmacVerify(CryptoHash hash, const char[] message, const char[] mac,
	                              CryptoEncoding macEncoding = CryptoEncoding_Hex, int messageLength = -1,
	                              int macLength = -1);

	/**
	 * Encrypts and authenticates a plaintext into a sealed message that only
	 * this key opens and that cannot be changed unnoticed. Each call uses a
	 * new random nonce, so sealing the same plaintext twice gives different
	 * messages. Seal at most 2^32 messages with one key.
	 *
	 * The message is the format byte, the nonce (12 bytes), the ciphertext
	 * (as long as the plaintext) and the tag (16 bytes); docs/formats.md
	 * tells how to read it elsewhere.
	 *
	 * @param plaintext        The plaintext.
	 * @param output           Receives the sealed message.
	 * @param maxlength        The size of output: Crypto.SealedSize(plaintextLength, encoding, cipher)
	 *                         or more.
	 * @param encoding         How the sealed message is written.
	 * @param cipher           The cipher; the key must have its size.
	 * @param aad              Additional data the message is bound to without
	 *                         holding it, e.g. a player's SteamID; Open must be
	 *                         given the same. "" for none.
	 * @param plaintextLength  The plaintext's length, or -1 for up to its NUL.
	 * @param aadLength        The length of aad, or -1 for up to its NUL.
	 * @return                 The bytes written, without the NUL.
	 * @error                  An invalid argument, a key of the wrong size for
	 *                         cipher or a buffer too small.
	 */
	public native int Seal(const char[] plaintext, char[] output, int maxlength,
	                       CryptoEncoding encoding = CryptoEncoding_Base64,
	                       CryptoCipher cipher = CryptoCipher_AES256GCM, const char[] aad = "",
	                       int plaintextLength = -1, int aadLength = -1);

	/**
	 * Opens a sealed message: checks it and writes its plaintext, followed
	 * by a NUL. The cipher is read from the message.
	 *
	 * @param message       The sealed message, in encoding.
	 * @param output        Receives the plaintext. A buffer as large as the
	 *                      sealed message's text always fits.
	 * @param maxlength     The size of output.
	 * @param encoding      The sealed message's encoding.
	 * @param aad           The additional data it was sealed with; "" for none.
	 * @param messageLength The sealed message's length, or -1 for up to its
	 *                      NUL; needed for CryptoEncoding_Raw.
	 * @param aadLength     The length of aad, or -1 for up to its NUL.
	 * @return              The plaintext's length; -1 when the message does
	 *                      not open: it is not valid in encoding, was changed,
	 *                      was sealed with another key or aad, or is no
	 *                      sealed message. Nothing is written then.
	 * @error               An invalid argument, or a buffer too small for a
	 *                      message that opened.
	 */
	public native int Open(const char[] message, char[] output, int maxlength,
	                       CryptoEncoding encoding = CryptoEncoding_Base64, const char[] aad = "",
	                       int messageLength = -1, int aadLength = -1);
}

/**
 * A hash or HMAC fed in pieces, e.g. a message put together from several
 * strings. Final or Verify ends it; after that only Hash and IsFinished may
 * be used. Delete it when done.
 */
methodmap CryptoDigest < Handle {
	/**
	 * Starts a hash.
	 *
	 * @error  An invalid hash.
	 */
	public native CryptoDigest(CryptoHash hash);

	/**
	 * Starts an HMAC with a key, which the digest copies: the key may be
	 * deleted after this.
	 *
	 * @error  An invalid hash or key.
	 */
	public static native CryptoDigest Hmac(CryptoHash hash, CryptoKey key);

	/** The hash function. */
	property CryptoHash Hash {
		public native get();
	}

	/** Whether Final or Verify ended the digest, or an Update failed. */
	property bool IsFinished {
		public native get();
	}

	/**
	 * Adds bytes.
	 *
	 * @param data        The bytes.
	 * @param dataLength  Their number, or -1 for up to the NUL.
	 * @error             An invalid length or a finished digest.
	 */
	public native void Update(const char[] data, int dataLength = -1);

	/**
	 * Ends the digest and writes it.
	 *
	 * @param output     Receives the digest.
	 * @param maxlength  The size of output: Crypto.EncodedSize(Crypto.HashSize(hash), encoding) or more.
	 * @param encoding   How the digest is written.
	 * @return           The bytes written, without the NUL.
	 * @error            An invalid argument, a buffer too small or a finished digest.
	 */
	public native int Final(char[] output, int maxlength, CryptoEncoding encoding = CryptoEncoding_Hex);

	/**
	 * Ends the digest and compares it with an expected one in constant time.
	 * The digest ends also when expected is not valid in its encoding.
	 *
	 * @param expected        The expected digest, in encoding.
	 * @param encoding        Its encoding.
	 * @param expectedLength  Its length, or -1 for up to its NUL; needed for
	 *                        CryptoEncoding_Raw.
	 * @return                true when they are equal; false when not, also
	 *                        when expected is not valid in its encoding.
	 * @error                 An invalid argument or a finished digest.
	 */
	public native bool Verify(const char[] expected, CryptoEncoding encoding = CryptoEncoding_Hex,
	                          int expectedLength = -1);
}

/**
 * Do not edit below this line!
 */
public Extension __ext_smcrypto = {
	name = "SMCrypto",
	file = "smcrypto.ext",
#if defined AUTOLOAD_EXTENSIONS
	autoload = 1,
#else
	autoload = 0,
#endif
#if defined REQUIRE_EXTENSIONS
	required = 1,
#else
	required = 0,
#endif
};

#if !defined REQUIRE_EXTENSIONS
public void __ext_smcrypto_SetNTVOptional() {
	MarkNativeAsOptional("Crypto.HashSize");
	MarkNativeAsOptional("Crypto.IsHashSupported");
	MarkNativeAsOptional("Crypto.IsCipherSupported");
	MarkNativeAsOptional("Crypto.Hash");
	MarkNativeAsOptional("Crypto.HashFile");
	MarkNativeAsOptional("Crypto.Cancel");
	MarkNativeAsOptional("Crypto.EncodedSize");
	MarkNativeAsOptional("Crypto.Encode");
	MarkNativeAsOptional("Crypto.Decode");
	MarkNativeAsOptional("Crypto.Random");
	MarkNativeAsOptional("Crypto.RandomInt");
	MarkNativeAsOptional("Crypto.Equal");
	MarkNativeAsOptional("Crypto.SealedSize");
	MarkNativeAsOptional("Crypto.ErrorString");
	MarkNativeAsOptional("CryptoKey.Generate");
	MarkNativeAsOptional("CryptoKey.Import");
	MarkNativeAsOptional("CryptoKey.FromString");
	MarkNativeAsOptional("CryptoKey.Length.get");
	MarkNativeAsOptional("CryptoKey.Export");
	MarkNativeAsOptional("CryptoKey.Derive");
	MarkNativeAsOptional("CryptoKey.Hmac");
	MarkNativeAsOptional("CryptoKey.HmacVerify");
	MarkNativeAsOptional("CryptoKey.Seal");
	MarkNativeAsOptional("CryptoKey.Open");
	MarkNativeAsOptional("CryptoDigest.CryptoDigest");
	MarkNativeAsOptional("CryptoDigest.Hmac");
	MarkNativeAsOptional("CryptoDigest.Hash.get");
	MarkNativeAsOptional("CryptoDigest.IsFinished.get");
	MarkNativeAsOptional("CryptoDigest.Update");
	MarkNativeAsOptional("CryptoDigest.Final");
	MarkNativeAsOptional("CryptoDigest.Verify");
}
#endif
