/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The random generator: sizes, distinct outputs, and the bounds and spread
 * of RandomInt. */
#include "check.h"
#include "random.h"

#include <cstdint>
#include <limits>
#include <set>

using namespace smcrypto;

TEST(RandomBytesHaveTheirSizeAndDiffer)
{
	std::set<std::string> seen;
	for (int i = 0; i < 100; i++) {
		SecretBytes bytes = MUST(RandomBytes(16));
		CHECK(bytes.size() == 16);
		seen.insert(std::string(bytes.begin(), bytes.end()));
	}
	CHECK(seen.size() == 100);
	CHECK(MUST(RandomBytes(65536)).size() == 65536);
}

TEST(RandomIntStaysInItsBounds)
{
	for (int i = 0; i < 1000; i++) {
		int32_t value = MUST(RandomInt(-3, 3));
		CHECK(value >= -3 && value <= 3);
	}
	CHECK(MUST(RandomInt(7, 7)) == 7);
	constexpr int32_t kMin = std::numeric_limits<int32_t>::min();
	constexpr int32_t kMax = std::numeric_limits<int32_t>::max();
	CHECK(MUST(RandomInt(kMax, kMax)) == kMax);
	CHECK(MUST(RandomInt(kMin, kMin)) == kMin);
	bool isNegativeSeen = false, isPositiveSeen = false;
	for (int i = 0; i < 200; i++) {
		int32_t value = MUST(RandomInt(kMin, kMax));
		isNegativeSeen = isNegativeSeen || value < 0;
		isPositiveSeen = isPositiveSeen || value > 0;
	}
	CHECK(isNegativeSeen && isPositiveSeen);
}

TEST(RandomIntHitsEveryValueAboutEquallyOften)
{
	constexpr int kValues = 6;
	constexpr int kDraws = 60000;
	int counts[kValues] = {};
	for (int i = 0; i < kDraws; i++)
		counts[MUST(RandomInt(1, kValues)) - 1]++;
	/* 10000 expected per value; 5 % off is over 12 standard deviations. */
	for (int count : counts)
		CHECK(count > 9500 && count < 10500);
}

TEST(ConstantTimeEqualComparesBytesAndSizes)
{
	std::string a = "abcdef", b = "abcdef", c = "abcdeg", d = "abcde";
	CHECK(ConstantTimeEqual(ByteView(a), ByteView(b)));
	CHECK(!ConstantTimeEqual(ByteView(a), ByteView(c)));
	CHECK(!ConstantTimeEqual(ByteView(a), ByteView(d)));
	CHECK(ConstantTimeEqual(ByteView(), ByteView()));
}
