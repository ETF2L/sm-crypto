/* Copyright 2026 ETF2L Contributors, Dave
 *
 * Runs every registered test, each with a fresh directory below the
 * system's temp directory:
 *   smcrypto-tests [name filter] */
#include "check.h"

#include <stdlib.h>
#include <string.h>

#include <chrono>
#include <filesystem>

namespace tests {

namespace {

std::string g_workDirectory;

} // namespace

std::vector<TestCase> &Registry()
{
	static std::vector<TestCase> registry;
	return registry;
}

int &Failures()
{
	static int failures = 0;
	return failures;
}

const std::string &WorkDirectory()
{
	return g_workDirectory;
}

smcrypto::Bytes FromHex(const char *hex)
{
	smcrypto::Bytes bytes;
	for (size_t i = 0; hex[i] && hex[i + 1]; i += 2) {
		char pair[3] = {hex[i], hex[i + 1], '\0'};
		bytes.push_back(static_cast<uint8_t>(strtoul(pair, nullptr, 16)));
	}
	return bytes;
}

std::string ToHex(smcrypto::ByteView bytes)
{
	static const char kDigits[] = "0123456789abcdef";
	std::string hex;
	for (size_t i = 0; i < bytes.size; i++) {
		hex += kDigits[bytes.data[i] >> 4];
		hex += kDigits[bytes.data[i] & 0x0f];
	}
	return hex;
}

} // namespace tests

int main(int argc, char **argv)
{
	setvbuf(stdout, nullptr, _IONBF, 0);
	const char *filter = argc > 1 ? argv[1] : "";
	smcrypto::Status started = smcrypto::InitializeLibrary();
	if (!started.IsOk()) {
		fprintf(stderr, "%s\n", started.Error().Describe().c_str());
		return EXIT_FAILURE;
	}
	printf("%s\n", smcrypto::LibraryVersion());

	auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
	std::filesystem::path root = std::filesystem::temp_directory_path() / ("smcrypto-tests-" + std::to_string(stamp));
	std::filesystem::create_directories(root);

	int run = 0;
	for (const tests::TestCase &test : tests::Registry()) {
		if (!strstr(test.name, filter))
			continue;
		std::filesystem::path directory = root / test.name;
		std::filesystem::create_directories(directory);
		tests::g_workDirectory = directory.string();
		int before = tests::Failures();
		test.body();
		run++;
		printf("%-56s %s\n", test.name, tests::Failures() == before ? "ok" : "FAILED");
	}
	std::filesystem::remove_all(root);
	smcrypto::ShutdownLibrary();
	printf("%d test(s), %d check(s) failed\n", run, tests::Failures());
	return tests::Failures() == 0 && run > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
