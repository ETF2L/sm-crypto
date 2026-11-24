/* Copyright 2026 ETF2L Contributors, Dave */
#include "paths.h"

namespace smcrypto {

bool IsGameRelativePath(std::string_view path)
{
	/* A NUL would end the path early for the file system. */
	constexpr std::string_view kRefused("\\:\0", 3);
	if (path.empty() || path.find_first_of(kRefused) != std::string_view::npos)
		return false;
	size_t start = 0;
	for (;;) {
		size_t end = path.find('/', start);
		std::string_view part = path.substr(start, end == std::string_view::npos ? std::string_view::npos : end - start);
		if (part.empty() || part == "." || part == "..")
			return false;
		if (end == std::string_view::npos)
			return true;
		start = end + 1;
	}
}

} // namespace smcrypto
