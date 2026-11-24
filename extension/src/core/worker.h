/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The worker thread that hashes files, one job after the other in the order
 * they were queued. The main thread queues jobs, cancels them and takes the
 * finished ones; a queued job that is cancelled is finished at once as
 * Cancelled, a running one stops at its next chunk. Destroying the worker
 * stops the running job and drops every other. */
#ifndef SMCRYPTO_CORE_WORKER_H
#define SMCRYPTO_CORE_WORKER_H

#include "file_hash.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace smcrypto {

using JobId = int32_t;

struct FileHashJob {
	JobId id = 0;
	Hash hash = Hash::SHA256;
	std::string path; /* absolute */
};

struct FinishedJob {
	JobId id = 0;
	FileHashOutcome outcome;
};

class Worker {
public:
	Worker();
	~Worker();

	Worker(const Worker &) = delete;
	Worker &operator=(const Worker &) = delete;

	/* Throws std::bad_alloc, with nothing queued, when memory runs out. */
	void Queue(FileHashJob job);

	/* Cancels a queued or running job; false when it has finished (or was
	 * never queued). */
	bool Cancel(JobId id);

	/* The jobs finished since the last call, in the order they finished.
	 * Throws std::bad_alloc, taking none, when memory runs out. */
	std::vector<FinishedJob> TakeFinished();

private:
	void Run();

	std::mutex m_mutex;
	std::condition_variable m_wake;
	std::deque<FileHashJob> m_queue;
	/* Its capacity always holds every job not yet ended (Queue). */
	std::vector<FinishedJob> m_finished;
	JobId m_runningId = 0;
	/* Read by the running job between chunks. */
	std::atomic<bool> m_isRunningCancelled{false};
	bool m_isStopping = false;
	std::thread m_thread;
};

} // namespace smcrypto

#endif // SMCRYPTO_CORE_WORKER_H
