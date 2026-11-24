/* Copyright 2026 ETF2L Contributors, Dave */
#include "worker.h"

#include <algorithm>
#include <iterator>
#include <new>

namespace smcrypto {

namespace {

FinishedJob CancelledJob(JobId id)
{
	FinishedJob finished;
	finished.id = id;
	finished.outcome.error = FileError::Cancelled;
	return finished;
}

/* HashFile, with an allocation failure told as Internal without a library
 * error: an exception that left the worker thread would end the server. */
FileHashOutcome HashFileOnWorker(const FileHashJob &job, const std::atomic<bool> &isCancelled)
{
	try {
		return HashFile(job.hash, job.path, isCancelled);
	} catch (const std::bad_alloc &) {
		FileHashOutcome outcome;
		outcome.error = FileError::Internal;
		return outcome;
	}
}

} // namespace

Worker::Worker() : m_thread(&Worker::Run, this) {}

Worker::~Worker()
{
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_isStopping = true;
		m_isRunningCancelled = true;
		m_queue.clear();
	}
	m_wake.notify_all();
	m_thread.join();
}

void Worker::Queue(FileHashJob job)
{
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		m_queue.push_back(std::move(job));
		/* Room in the finished list for every job that has not ended, so
		 * that ending one never allocates: neither the worker thread nor
		 * Cancel can then fail to report a job. It grows geometrically, so a
		 * burst of jobs does not move the list on every one. */
		size_t unfinished = m_queue.size() + (m_runningId != 0 ? 1 : 0);
		size_t needed = m_finished.size() + unfinished;
		try {
			if (needed > m_finished.capacity())
				m_finished.reserve(std::max(needed, 2 * m_finished.capacity()));
		} catch (...) {
			m_queue.pop_back();
			throw;
		}
	}
	m_wake.notify_one();
}

bool Worker::Cancel(JobId id)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	if (id == m_runningId && id != 0) {
		m_isRunningCancelled = true;
		return true;
	}
	auto queued = std::find_if(m_queue.begin(), m_queue.end(), [id](const FileHashJob &job) { return job.id == id; });
	if (queued == m_queue.end())
		return false;
	m_queue.erase(queued);
	m_finished.push_back(CancelledJob(id));
	return true;
}

std::vector<FinishedJob> Worker::TakeFinished()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	/* Moved out rather than swapped, so m_finished keeps the room Queue
	 * reserved; when the copy cannot be allocated nothing is taken. */
	std::vector<FinishedJob> finished;
	finished.reserve(m_finished.size());
	std::move(m_finished.begin(), m_finished.end(), std::back_inserter(finished));
	m_finished.clear();
	return finished;
}

void Worker::Run()
{
	std::unique_lock<std::mutex> lock(m_mutex);
	for (;;) {
		m_wake.wait(lock, [this] { return m_isStopping || !m_queue.empty(); });
		if (m_isStopping)
			return;
		FileHashJob job = std::move(m_queue.front());
		m_queue.pop_front();
		m_runningId = job.id;
		m_isRunningCancelled = false;

		lock.unlock();
		FileHashOutcome outcome = HashFileOnWorker(job, m_isRunningCancelled);
		lock.lock();

		m_runningId = 0;
		if (m_isStopping)
			return;
		m_finished.push_back(FinishedJob{job.id, std::move(outcome)});
	}
}

} // namespace smcrypto
