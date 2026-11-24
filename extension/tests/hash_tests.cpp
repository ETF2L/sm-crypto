/* Copyright 2026 ETF2L Contributors, Dave
 *
 * Every hash against its standard's "abc" vector, the empty input, a
 * million "a" (FIPS 180-2), and streams against one-shot hashes. */
#include "check.h"
#include "hash.h"

#include <algorithm>
#include <string>

using namespace smcrypto;

namespace {

struct Vector {
	Hash hash;
	size_t size;
	const char *abc;
	const char *emptyPrefix; /* the first 8 bytes of the empty input's digest */
};

const Vector kVectors[kHashCount] = {
	{Hash::SHA256, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "e3b0c44298fc1c14"},
	{Hash::SHA224, 28, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", "d14a028c2a3a2bc9"},
	{Hash::SHA384, 48,
	 "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
	 "38b060a751ac9638"},
	{Hash::SHA512, 64,
	 "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce"
	 "80e2a9ac94fa54ca49f",
	 "cf83e1357eefb8bd"},
	{Hash::SHA3_224, 28, "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf", "6b4e03423667dbb7"},
	{Hash::SHA3_256, 32, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", "a7ffc6f8bf1ed766"},
	{Hash::SHA3_384, 48,
	 "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
	 "0c63a75b845e4f7d"},
	{Hash::SHA3_512, 64,
	 "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d"
	 "5a56592f8274eec53f0",
	 "a69f73cca23a9ac5"},
	{Hash::SHA1, 20, "a9993e364706816aba3e25717850c26c9cd0d89d", "da39a3ee5e6b4b0d"},
	{Hash::MD5, 16, "900150983cd24fb0d6963f7d28e17f72", "d41d8cd98f00b204"},
};

} // namespace

TEST(EveryHashMatchesItsStandardVectors)
{
	for (const Vector &vector : kVectors) {
		CHECK(HashSize(vector.hash) == vector.size);
		CHECK(HashSize(vector.hash) <= kMaxHashSize);
		CHECK_EQ_STR(tests::ToHex(MUST(ComputeHash(vector.hash, ByteView(std::string("abc"))))), vector.abc);
		CHECK_EQ_STR(tests::ToHex(MUST(ComputeHash(vector.hash, ByteView()))).substr(0, 16), vector.emptyPrefix);
	}
}

TEST(AMillionAsHashLikeFips180)
{
	std::string input(1000000, 'a');
	CHECK_EQ_STR(tests::ToHex(MUST(ComputeHash(Hash::SHA256, ByteView(input)))),
	             "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(AStreamHashesLikeOneShot)
{
	std::string input;
	for (int i = 0; i < 5000; i++)
		input += static_cast<char>(i * 7);
	for (const Vector &vector : kVectors) {
		auto stream = MUST(HashStream::Start(vector.hash));
		if (!stream)
			continue;
		/* Pieces of growing size, an empty one among them. */
		size_t offset = 0;
		for (size_t piece = 0; offset < input.size(); piece++) {
			size_t size = std::min(piece * 13, input.size() - offset);
			CHECK(stream->Update(ByteView(reinterpret_cast<const uint8_t *>(input.data()) + offset, size)).IsOk());
			offset += size;
		}
		CHECK(MUST(stream->Finish()) == MUST(ComputeHash(vector.hash, ByteView(input))));
	}
}

TEST(AFinishedStreamRefusesMore)
{
	auto stream = MUST(HashStream::Start(Hash::SHA256));
	CHECK(stream->Finish().IsOk());
	CHECK(!stream->Update(ByteView(std::string("x"))).IsOk());
	CHECK(!stream->Finish().IsOk());
}

TEST(HashNamesAreTheStandardsNames)
{
	CHECK_EQ_STR(HashName(Hash::SHA256), "SHA-256");
	CHECK_EQ_STR(HashName(Hash::SHA3_512), "SHA3-512");
	CHECK_EQ_STR(HashName(Hash::MD5), "MD5");
}
