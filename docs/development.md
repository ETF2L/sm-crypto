# Development

## Building

`.github/workflows/ci.yml` builds SMCrypto, and its jobs are the reference for a local build. The `linux` job, on an
Ubuntu 22.04 runner:

1. vcpkg at the commit `vcpkg/vcpkg.json` names as its `builtin-baseline` builds Mbed TLS for both architectures into
   `libs/x86` and `libs/x64`, with the triplets of `vcpkg/triplets/` and vcpkg's packages cached.
2. AMBuild builds `smcrypto.ext.so` and the unit tests against SourceMod's headers
   (`extension/configure.py --targets=x86,x86_64 --sm-path=<sourcemod> --libs-path=<libs>`), SourceMod and AMBuild at
   the commits `toolchain.json` pins; the tests run on both architectures, and the binaries are checked to export only
   `GetSMExtAPI` and need at most glibc 2.35.
3. It packs `sm-crypto-<label>-linux.tar.gz`, laid out like a game folder.
4. sm-runner's setup and test actions (`davenonymous/sm-runner/setup@v0` and `test@v0`) run the SourcePawn tests and
   the examples' tests against the packed extension, with both `smrunner` and `smrunner64`. A failing test fails the
   job, so no release is published.

The `windows` job runs `windows/build.py`, which works on its own on any Windows machine with Visual Studio 2022 (or
its Build Tools) with the C++ tools, git and Python 3.8 or newer:

```
python windows\build.py --work C:\build\smcrypto --out C:\build\smcrypto\out
```

It fetches vcpkg (at the commit `vcpkg/vcpkg.json` pins), SourceMod's headers and AMBuild (in a virtual environment,
both at the commits `toolchain.json` pins) into the work directory, again only when a pin moved, builds Mbed TLS with
the static runtime (`/MT`, as SourceMod uses), builds each architecture inside its own MSVC environment, runs the unit
tests natively and refuses a DLL that exports more than `GetSMExtAPI` or needs a DLL beyond Windows' own (it may need
only `kernel32.dll`, `user32.dll`, `advapi32.dll` and `bcrypt.dll`). The job packs `sm-crypto-<label>-windows.zip`.

For a pushed `v*` tag the `release` job publishes both archives, after checking the tag against the version in
`extension/src/version.h`.

## Tests

- **Unit tests** (`extension/tests/`): the core without SourceMod, on Linux x86 and x86_64 and on Windows x86 and x64.
  Every hash against its standard's vectors (and a million "a" for SHA-256), HMAC against RFC 4231, HKDF against RFC
  5869, sealed messages against vectors that `tools/sealed_vectors.py` makes with Python's cryptography package,
  every changed byte of a sealed message refused, the encodings against RFC 4648 and every non-canonical text refused,
  the random generator's range and spread, file hashing across chunk boundaries, the worker's order and cancellation,
  the path rule, the native call over a fake plugin (spans that cross the gap between heap and stack or leave the
  memory, strings without a NUL, lengths, arguments not passed, outputs that do not fit), and the file jobs (refused
  jobs, who may cancel, dropped job owners, the order of delivery, ids that start over).
  `smcrypto-tests-<arch> [filter]` runs the tests whose name contains filter.
- **SourcePawn tests** (`tests/test_smcrypto.sp`): every native as a plugin calls it, under smrunner: vectors, every
  encoding, binary data, the documented native errors (through `Runner.ExpectError`), memory that runs past the
  plugin, file jobs on the worker thread with their errors and cancellation, and keys of another plugin
  (`tests/key-holder.sp`) out of reach. `tests/test_examples.sp` runs the four examples through their commands, with
  a connected player for the signed links. Both need [sm-runner](https://github.com/davenonymous/sm-runner)'s
  smrunner. Compile them with `scripting/include` and smrunner's `share/include` on the include path, then run them
  against an extension folder laid out like `addons/sourcemod/extensions` (the packed archive's):

  ```
  smrunner test test_smcrypto.smx --extensions <dist>/extensions --plugin key-holder.smx
  smrunner test test_examples.smx --extensions <dist>/extensions \
      --plugin hash-text.smx --plugin verify-file.smx --plugin signed-links.smx --plugin sealed-notes.smx
  ```

  `smrunner` loads the x86 extension, `smrunner64` the x64 one.
- **CI** (`.github/workflows/ci.yml`): builds both systems and runs the unit tests on every push, runs the SourcePawn
  tests and the examples' tests under smrunner on Linux, and checks the SourcePawn files in `scripting/`, `examples/`
  and `tests/` with pawncritic and `pawntidy --check` (sourcepawn-tools' SourcePawn Lint action).

The Windows DLLs have been tested by their unit tests only, not on a Windows game server.

## Layout

| Path | What |
|---|---|
| `extension/src/core/` | The core, without SourceMod: `library` (Mbed TLS start and errors), `bytes` (buffers that wipe themselves), `encoding`, `hash`, `keyed` (HMAC, HKDF), `sealed`, `random`, `digest`, `file_hash`, `worker`, `file_jobs` (ids, job owners, refused jobs, the order of delivery), `paths`, `native_call` (argument count, argument readers and writers, memory checks, over the `CallingPlugin` seam); `psa_key.h` imports a key for one operation. |
| `extension/src/` | The SourceMod layer: `extension` (handle types, the frame hook that calls file jobs back), `crypto_error` (the include's `CryptoError`), `natives_common` (`CallingPlugin` over SourcePawn, `PluginCall` with handles, callbacks and game paths, `Checked<>`), `natives_crypto`, `natives_key`, `natives_digest`. |
| `extension/tests/` | The unit tests; `tools/sealed_vectors.py` makes the sealed vectors. |
| `scripting/include/smcrypto.inc` | The include. |
| `examples/` | The example plugins. |
| `tests/` | The SourcePawn tests for smrunner, with `key-holder.sp`, a plugin whose key the tests must not reach. |
| `vcpkg/` | The manifest and the triplets. |
| `toolchain.json` | The SourceMod and AMBuild commits every build uses. |
| `windows/build.py` | The Windows build. |

Only `library.cpp` uses Mbed TLS outside its PSA Crypto API; the other files that include `psa/crypto.h` call PSA only,
so that an update to Mbed TLS 4, which keeps the PSA API and makes the older functions private, needs no code changes. A
native gets only its `PluginCall` (a `NativeCall` of the core): every argument is read and every output written through
it, so no span of plugin memory escapes its checks (inside one part of the memory, never across the gap between heap and
stack, and refused when the plugin's stack is unknown) and no argument the plugin did not pass is read. Natives check
every argument completely and hand the core only valid values; the core does not check them again, except that sealing
throws `std::invalid_argument` for a key or nonce of the wrong size rather than letting the library take a short key for
another cipher. `Checked<>` turns any exception that leaves a native (that one, or `std::bad_alloc`) into a native
error, and the worker tells an allocation failure as `CryptoError_Internal`, so no exception unwinds through the VM or
ends the worker thread. Queuing a file job reserves the room its end needs in the worker's finished list, so ending,
cancelling or dropping a job never allocates; the frame hook catches what is left: when the ended jobs cannot be taken,
it delivers none and tries again on the next frame, and when a job's digest cannot be encoded, it calls the job back
with `CryptoError_Internal` and no digest. `FileJobs` delivers the refused jobs of a frame before the jobs the worker
ended, and takes each job out right before its callback, so a job whose owner was unloaded meanwhile, even by an earlier
callback of the same frame, is not delivered.

Adding a hash: a value at the end of `Hash` in `hash.h` and of `CryptoHash` in the include, `kHashCount` raised, its
rows in `kHas` and `kHashes` (`hash.cpp`), its vectors in both test suites. Adding a cipher: a value at the end of
`Cipher` in `sealed.h` and of `CryptoCipher`, `kCipherCount` raised, its row in `kCiphers` (`sealed.cpp`) with a new
format byte (never reuse one) and its nonce and tag sizes, vectors from
`sealed_vectors.py`, and `docs/formats.md`. Enum values never change. A new argument goes at the end of a native,
with a default; the native reads it only when `call.IsPassed(n)` says the plugin passed it (`call.Arg(n)` throws
otherwise, a native error), and its count in the native table stays the old one.

## Updating SourceMod and AMBuild

Move the commits in `toolchain.json` (`windows/build.py` and the CI read them from there), keeping SourceMod on the
branch the shared toolchain image follows (`1.12-dev`), and let CI build (Linux and Windows).

## Updating Mbed TLS

Move `builtin-baseline` in `vcpkg/vcpkg.json` to a newer vcpkg commit (`windows/build.py` and the CI read it from there)
and the `overrides` entry to the version that commit's `mbedtls` port has, let CI build (Linux and Windows) and check
the new sources: everything that touches Mbed TLS's global state runs on the main thread, since it is built without
threads, and the worker relies on `psa_hash_setup`, `psa_hash_update`, `psa_hash_finish` and `psa_hash_abort` touching
no global state. As long as the port stays on 3.6 LTS nothing else changes.

Mbed TLS 4 moves the crypto library into TF-PSA-Crypto. The PSA calls stay; what may move is all in one file and two
build paths, and `library.cpp` refuses to compile against another major version until it is checked:

- `extension/src/core/library.cpp`: the version macro and `<mbedtls/build_info.h>`, `mbedtls_psa_crypto_free`,
  `mbedtls_platform_zeroize` (`<mbedtls/platform_util.h>`);
- the library's name (`mbedcrypto`) in `extension/AMBuildScript`;
- the license file `share/mbedtls/copyright` in `.github/workflows/ci.yml`.

## Releasing

Set `SMCRYPTO_VERSION_STRING` in `extension/src/version.h`, commit, and push a tag `v<version>` to `etf2l/sm-crypto`;
the workflow (`.github/workflows/ci.yml`) checks the tag against `version.h` and publishes
`sm-crypto-v<version>-linux.tar.gz` and `sm-crypto-v<version>-windows.zip`, each laid out like a game folder
(`addons/sourcemod/...`).
