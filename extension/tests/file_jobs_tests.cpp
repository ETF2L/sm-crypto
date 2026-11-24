/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The file jobs as plugins see them: refused jobs, who may cancel, dropped
 * owners, the order of delivery and ids that start over. */
#include "check.h"
#include "file_jobs.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>

using namespace smcrypto;

namespace {

/* Owners are plugin numbers, tickets the path as given. */
using Jobs = FileJobs<int, std::string>;

struct Delivered {
	JobId id;
	int owner;
	std::string ticket;
	FileError error;
	int batch; /* the DeliverEnded call it came in */
};

std::string WriteFile(const std::string &name, size_t size)
{
	std::string path = (std::filesystem::path(tests::WorkDirectory()) / name).string();
	std::ofstream(path, std::ios::binary) << std::string(size, 'f');
	return path;
}

/* Delivers until count jobs arrived or seconds passed, at least once. */
std::vector<Delivered> DeliverAll(Jobs &jobs, size_t count, int seconds = 10)
{
	std::vector<Delivered> delivered;
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
	for (int batch = 0;; batch++) {
		jobs.DeliverEnded([&](Jobs::EndedJob &&job) {
			delivered.push_back(Delivered{job.id, job.owner, job.ticket, job.outcome.error, batch});
		});
		if (delivered.size() >= count || std::chrono::steady_clock::now() >= deadline)
			return delivered;
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}
}

} // namespace

TEST(ARefusedJobEndsAtOnceWithInvalidPath)
{
	Jobs jobs;
	JobId refused = jobs.Refuse(1, "../outside");
	CHECK(refused == 1);
	CHECK(!jobs.Cancel(1, refused));
	std::vector<Delivered> delivered = DeliverAll(jobs, 1);
	CHECK(delivered.size() == 1);
	CHECK(delivered.size() == 1 && delivered[0].id == refused && delivered[0].owner == 1 &&
	      delivered[0].ticket == "../outside" && delivered[0].error == FileError::InvalidPath);
	CHECK(DeliverAll(jobs, 1, 0).empty());
}

TEST(RefusedJobsComeBeforeTheWorkersInOneDelivery)
{
	Jobs jobs;
	std::string small = WriteFile("small", 10);
	JobId hashed = jobs.Queue(1, "small", Hash::SHA256, small);
	/* Cancels the job until Cancel tells it ended: then the worker has
	 * reported it (as cancelled or hashed), not yet delivered. */
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	while (jobs.Cancel(1, hashed) && std::chrono::steady_clock::now() < deadline)
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
	JobId refused = jobs.Refuse(1, "../outside");
	std::vector<Delivered> delivered = DeliverAll(jobs, 2, 0);
	CHECK(delivered.size() == 2);
	if (delivered.size() != 2)
		return;
	CHECK(delivered[0].id == refused && delivered[1].id == hashed);
	CHECK(delivered[0].batch == 0 && delivered[1].batch == 0);
}

TEST(OnlyTheOwnerCancelsAJob)
{
	Jobs jobs;
	std::string big = WriteFile("big", 64 * kFileChunkSize);
	JobId first = jobs.Queue(1, "big", Hash::SHA512, big);
	JobId second = jobs.Queue(1, "big", Hash::SHA512, big);
	CHECK(!jobs.Cancel(2, second));
	CHECK(!jobs.Cancel(1, 42));
	CHECK(jobs.Cancel(1, second));
	std::vector<Delivered> delivered = DeliverAll(jobs, 2);
	CHECK(delivered.size() == 2);
	for (const Delivered &job : delivered)
		CHECK(job.error == (job.id == first ? FileError::None : FileError::Cancelled));
	CHECK(!jobs.Cancel(1, first));
}

TEST(ADroppedOwnersJobsEndUnreported)
{
	Jobs jobs;
	std::string big = WriteFile("big", 64 * kFileChunkSize);
	jobs.Queue(1, "big", Hash::SHA512, big);
	jobs.Queue(1, "big", Hash::SHA512, big);
	jobs.Refuse(1, "../outside");
	JobId kept = jobs.Refuse(2, "../other");
	jobs.DropOwner(1);
	/* Long enough for the worker to report its cancelled jobs. */
	std::vector<Delivered> delivered = DeliverAll(jobs, 2, 1);
	CHECK(delivered.size() == 1);
	CHECK(delivered.size() == 1 && delivered[0].id == kept && delivered[0].owner == 2);
}

TEST(AJobDroppedDuringADeliveryIsNotDelivered)
{
	Jobs jobs;
	jobs.Refuse(1, "first");
	jobs.Refuse(2, "second");
	std::vector<JobId> delivered;
	jobs.DeliverEnded([&](Jobs::EndedJob &&job) {
		delivered.push_back(job.id);
		jobs.DropOwner(2);
		jobs.Refuse(3, "during");
	});
	CHECK(delivered.size() == 1 && delivered[0] == 1);
	/* The job refused during the delivery comes with the next one. */
	std::vector<Delivered> next = DeliverAll(jobs, 1, 0);
	CHECK(next.size() == 1 && next[0].owner == 3);
}

TEST(IdsStartOverSkippingJobsNotYetDelivered)
{
	Jobs jobs(3);
	CHECK(jobs.Refuse(1, "a") == 1);
	CHECK(jobs.Refuse(2, "b") == 2);
	CHECK(jobs.Refuse(1, "c") == 3);
	jobs.DropOwner(1);
	CHECK(jobs.Refuse(1, "d") == 1);
	CHECK(jobs.Refuse(1, "e") == 3);
}
