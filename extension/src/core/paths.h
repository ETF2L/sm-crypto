/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The rule for paths plugins pass: relative to the game directory and
 * staying below it, the same on Linux and Windows. */
#ifndef SMCRYPTO_CORE_PATHS_H
#define SMCRYPTO_CORE_PATHS_H

#include <string_view>

namespace smcrypto {

/* Not empty, "/" between parts, no part empty, "." or "..", and no "\",
 * ":" or NUL (no Windows separators, drive letters or "file://"). */
bool IsGameRelativePath(std::string_view path);

} // namespace smcrypto

#endif // SMCRYPTO_CORE_PATHS_H
