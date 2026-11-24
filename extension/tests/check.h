/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The tests' checks: a failed check is printed and counted, the program
 * exits non-zero when any failed. Tests register themselves with TEST(). */
#ifndef SMCRYPTO_TESTS_CHECK_H
#define SMCRYPTO_TESTS_CHECK_H

#include "bytes.h"
#include "library.h"

#include <stdio.h>

#include <functional>
#include <string>
#include <vector>

namespace tests {

struct TestCase {
	const char *name;
	std::function<void()> body;
};

std::vector<TestCase> &Registry();
int &Failures();

struct Registrar {
	Registrar(const char *name, std::function<void()> body) { Registry().push_back(TestCase{name, std::move(body)}); }
};

/* A directory of its own for the running test. */
const std::string &WorkDirectory();

/* Bytes from hex digits, for vectors. */
smcrypto::Bytes FromHex(const char *hex);

/* Lowercase hex digits of bytes. */
std::string ToHex(smcrypto::ByteView bytes);

/* The value of a Result that must be ok; a failure is counted and an empty
 * value returned. */
template <typename T>
T Must(smcrypto::Result<T> result, const char *file, int line)
{
	if (result.IsOk())
		return std::move(result.Value());
	fprintf(stderr, "%s:%d: library error: %s\n", file, line, result.Error().Describe().c_str());
	Failures()++;
	return T();
}

} // namespace tests

#define TEST_CONCAT2(a, b) a##b
#define TEST_CONCAT(a, b) TEST_CONCAT2(a, b)
#define TEST(name)                                                                                  \
	static void name();                                                                             \
	static tests::Registrar TEST_CONCAT(registrar_, name)(#name, name);                             \
	static void name()

#define CHECK(condition)                                                                            \
	do {                                                                                            \
		if (!(condition)) {                                                                         \
			fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition);           \
			tests::Failures()++;                                                                    \
		}                                                                                           \
	} while (0)

#define CHECK_EQ_STR(actual, expected)                                                              \
	do {                                                                                            \
		std::string actual_ = (actual);                                                             \
		std::string expected_ = (expected);                                                         \
		if (actual_ != expected_) {                                                                 \
			fprintf(stderr, "%s:%d: expected \"%s\", got \"%s\"\n", __FILE__, __LINE__,             \
			        expected_.c_str(), actual_.c_str());                                            \
			tests::Failures()++;                                                                    \
		}                                                                                           \
	} while (0)

#define MUST(result) tests::Must((result), __FILE__, __LINE__)

#endif // SMCRYPTO_TESTS_CHECK_H
