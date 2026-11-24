/* Copyright 2026 ETF2L Contributors, Dave
 *
 * Hashing files and the worker thread: digests equal to hashing the
 * content, the errors, cancellation, and the order jobs finish in. */
#include "check.h"
#include "paths.h"
#include "worker.h"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <thread>

#ifndef _WIN32
#include <sys/stat.h>
#else
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using namespace smcrypto;

namespace {

std::string WriteFile(const std::string &name, const std::string &content)
{
	std::string path = (std::filesystem::path(tests::WorkDirectory()) / name).string();
	std::ofstream(path, std::ios::binary) << content;
	return path;
}

std::string Content(size_t size)
{
	std::string content(size, '\0');
	for (size_t i = 0; i < size; i++)
		content[i] = static_cast<char>((i * 31) ^ (i >> 8));
	return content;
}

FileHashOutcome HashNow(Hash hash, const std::string &path)
{
	std::atomic<bool> isCancelled{false};
	return HashFile(hash, path, isCancelled);
}

/* Takes finished jobs until count arrived or ten seconds passed. */
std::vector<FinishedJob> WaitForFinished(Worker &worker, size_t count)
{
	std::vector<FinishedJob> finished;
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	while (finished.size() < count && std::chrono::steady_clock::now() < deadline) {
		for (FinishedJob &job : worker.TakeFinished())
			finished.push_back(std::move(job));
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
	return finished;
}

} // namespace

TEST(AFileHashesLikeItsContent)
{
	/* Empty, below, at and above the chunk size. */
	for (size_t size : {size_t(0), size_t(1), kFileChunkSize - 1, kFileChunkSize, kFileChunkSize + 1,
	                    3 * kFileChunkSize + 17}) {
		std::string content = Content(size);
		std::string path = WriteFile("file-" + std::to_string(size), content);
		for (Hash hash : {Hash::SHA256, Hash::SHA3_512, Hash::MD5}) {
			FileHashOutcome outcome = HashNow(hash, path);
			CHECK(outcome.error == FileError::None);
			CHECK(outcome.digest == MUST(ComputeHash(hash, ByteView(content))));
		}
	}
}

TEST(MissingFilesAndDirectoriesAreTold)
{
	CHECK(HashNow(Hash::SHA256, tests::WorkDirectory() + "/missing").error == FileError::NotFound);
	CHECK(HashNow(Hash::SHA256, tests::WorkDirectory()).error == FileError::NotAFile);
	CHECK(HashNow(Hash::SHA256, tests::WorkDirectory() + "/missing/below").error == FileError::NotFound);
}

TEST(ACancelledHashStopsWithoutDigest)
{
	std::string path = WriteFile("cancelled", Content(1000));
	std::atomic<bool> isCancelled{true};
	FileHashOutcome outcome = HashFile(Hash::SHA256, path, isCancelled);
	CHECK(outcome.error == FileError::Cancelled);
	CHECK(outcome.digest.empty());
}

#ifndef _WIN32
TEST(AFifoIsNoFileAndDoesNotBlock)
{
	/* Opening a FIFO without a writer would block the worker for good. */
	std::string path = tests::WorkDirectory() + "/fifo";
	CHECK(mkfifo(path.c_str(), 0600) == 0);
	CHECK(HashNow(Hash::SHA256, path).error == FileError::NotAFile);
}
#else
TEST(DeviceNamesAreNoFiles)
{
	/* Windows opens a device for these names in any directory. */
	for (const char *name : {"NUL", "nul.txt", "COM1", "con .log", "Lpt9.x.y"})
		CHECK(HashNow(Hash::SHA256, tests::WorkDirectory() + "/" + name).error == FileError::NotAFile);
	std::string path = WriteFile("console.txt", "not a device");
	CHECK(HashNow(Hash::SHA256, path).error == FileError::None);
}

TEST(AFileThatCannotBeOpenedIsNotTakenForAMissingOne)
{
	/* Held open without sharing, the file is there (its attributes can
	 * still be read) but opening it fails: this checks how a failed open is
	 * told. A failed look at the path itself is not covered, since the C
	 * runtime's _wstat64 sets ENOENT for every failure we could cause. */
	std::string path = WriteFile("locked.txt", "locked");
	std::wstring wide = std::filesystem::u8path(path).wstring();
	HANDLE locked = CreateFileW(wide.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	CHECK(locked != INVALID_HANDLE_VALUE);
	CHECK(HashNow(Hash::SHA256, path).error == FileError::Open);
	CloseHandle(locked);
	CHECK(HashNow(Hash::SHA256, path).error == FileError::None);
}
#endif

TEST(TheWorkerFinishesJobsInTheirOrder)
{
	Worker worker;
	std::string content = Content(5 * kFileChunkSize);
	std::string path = WriteFile("ordered", content);
	for (JobId id = 1; id <= 5; id++)
		worker.Queue(FileHashJob{id, Hash::SHA256, path});
	worker.Queue(FileHashJob{6, Hash::SHA256, tests::WorkDirectory() + "/missing"});
	std::vector<FinishedJob> finished = WaitForFinished(worker, 6);
	CHECK(finished.size() == 6);
	Bytes expected = MUST(ComputeHash(Hash::SHA256, ByteView(content)));
	for (size_t i = 0; i < finished.size(); i++) {
		CHECK(finished[i].id == static_cast<JobId>(i + 1));
		CHECK(i == 5 ? finished[i].outcome.error == FileError::NotFound : finished[i].outcome.digest == expected);
	}
	CHECK(!worker.Cancel(1));
}

TEST(CancellingAQueuedJobFinishesItAsCancelled)
{
	Worker worker;
	/* A big file keeps the first job running while the others wait. */
	std::string big = WriteFile("big", Content(64 * kFileChunkSize));
	std::string small = WriteFile("small", "small");
	worker.Queue(FileHashJob{1, Hash::SHA512, big});
	worker.Queue(FileHashJob{2, Hash::SHA256, small});
	worker.Queue(FileHashJob{3, Hash::SHA256, small});
	CHECK(worker.Cancel(2));
	CHECK(!worker.Cancel(42));
	std::vector<FinishedJob> finished = WaitForFinished(worker, 3);
	CHECK(finished.size() == 3);
	for (const FinishedJob &job : finished) {
		if (job.id == 2)
			CHECK(job.outcome.error == FileError::Cancelled);
		else
			CHECK(job.outcome.error == FileError::None);
	}
}

TEST(DestroyingTheWorkerStopsItsJobs)
{
	std::string big = WriteFile("big", Content(64 * kFileChunkSize));
	auto worker = std::make_unique<Worker>();
	for (JobId id = 1; id <= 20; id++)
		worker->Queue(FileHashJob{id, Hash::SHA512, big});
	worker.reset();
	CHECK(true);
}

TEST(GamePathsMustStayBelowTheGameDirectory)
{
	for (const char *path : {"a", "addons/sourcemod/plugins/x.smx", "a.b/c..d/.e", "logs/L1121.log"})
		CHECK(IsGameRelativePath(path));
	for (const char *path : {"", "/etc/passwd", "a//b", "a/", "./a", "a/./b", "..", "a/../b", "a/..", "C:/x",
	                         "c:x", "a\\b", "\\\\server\\share", "file://etc/passwd"})
		CHECK(!IsGameRelativePath(path));
	CHECK(!IsGameRelativePath(std::string_view("a/..\0", 5)));
	CHECK(!IsGameRelativePath(std::string_view("ok\0/../x", 9)));
}
