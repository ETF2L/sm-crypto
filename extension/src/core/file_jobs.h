/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The file jobs plugins queued, from their id to their delivery: ids above
 * 0 that start over after maxId, skipping jobs not yet delivered; the job
 * owner, the only one that may cancel a job, whose jobs end unreported when
 * it is dropped; refused jobs, which end at once with InvalidPath without
 * reaching the worker; and one order of delivery: the refused jobs, then
 * the jobs the worker ended, each in the order it ended them. The worker
 * thread only hashes, since Mbed TLS is built without threads and its
 * global state must stay on the main thread; everything here runs there.
 *
 * Owner is a token for the job owner, compared with ==; Ticket is what the
 * extension needs to call the job back, handed back at delivery. */
#ifndef SMCRYPTO_CORE_FILE_JOBS_H
#define SMCRYPTO_CORE_FILE_JOBS_H

#include "worker.h"

#include <algorithm>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace smcrypto {

template <typename Owner, typename Ticket>
class FileJobs {
public:
	/* A job as it is delivered. */
	struct EndedJob {
		JobId id = 0;
		Owner owner;
		Ticket ticket;
		FileHashOutcome outcome;
	};

	explicit FileJobs(JobId maxId = std::numeric_limits<JobId>::max()) : m_maxId(maxId) {}

	FileJobs(const FileJobs &) = delete;
	FileJobs &operator=(const FileJobs &) = delete;

	/* Queues the hashing of the file at absolutePath on the worker; returns
	 * the job's id. Throws std::bad_alloc, leaving no part of the job
	 * behind, when memory runs out. */
	JobId Queue(Owner owner, Ticket ticket, Hash hash, std::string absolutePath)
	{
		JobId id = Add(std::move(owner), std::move(ticket));
		try {
			m_worker.Queue(FileHashJob{id, hash, std::move(absolutePath)});
		} catch (...) {
			m_pending.erase(id);
			throw;
		}
		return id;
	}

	/* A refused job: it ends at once with InvalidPath, its path breaking
	 * the path rule, and is delivered like any other; returns its id.
	 * Throws std::bad_alloc like Queue. */
	JobId Refuse(Owner owner, Ticket ticket)
	{
		JobId id = Add(std::move(owner), std::move(ticket));
		try {
			m_refused.push_back(id);
		} catch (...) {
			m_pending.erase(id);
			throw;
		}
		return id;
	}

	/* Cancels a job of owner on the worker; false when owner has no such
	 * job, or it ended already: a refused job counts as ended at once. */
	bool Cancel(const Owner &owner, JobId id)
	{
		auto found = m_pending.find(id);
		if (found == m_pending.end() || !(found->second.owner == owner))
			return false;
		return m_worker.Cancel(id);
	}

	/* Ends every job of owner unreported: a queued or running one is
	 * cancelled on the worker. Allocates nothing. */
	void DropOwner(const Owner &owner)
	{
		for (auto it = m_pending.begin(); it != m_pending.end();) {
			if (!(it->second.owner == owner)) {
				++it;
				continue;
			}
			m_worker.Cancel(it->first);
			m_refused.erase(std::remove(m_refused.begin(), m_refused.end(), it->first), m_refused.end());
			it = m_pending.erase(it);
		}
	}

	/* Calls deliver(EndedJob &&) for every job that ended since the last
	 * call, in the order of delivery. A job is taken out right before its
	 * delivery, so deliver may queue, refuse, cancel and drop owners: a job
	 * dropped meanwhile is not delivered. deliver must not throw. Throws
	 * std::bad_alloc, delivering and taking nothing, when memory runs out. */
	template <typename Deliver>
	void DeliverEnded(Deliver &&deliver)
	{
		std::vector<FinishedJob> finished = m_worker.TakeFinished();
		std::vector<JobId> refused;
		refused.swap(m_refused);
		for (JobId id : refused) {
			FileHashOutcome outcome;
			outcome.error = FileError::InvalidPath;
			DeliverOne(id, std::move(outcome), deliver);
		}
		for (FinishedJob &job : finished)
			DeliverOne(job.id, std::move(job.outcome), deliver);
	}

private:
	struct Pending {
		Owner owner;
		Ticket ticket;
	};

	JobId Add(Owner owner, Ticket ticket)
	{
		JobId id = NextId();
		m_pending.emplace(id, Pending{std::move(owner), std::move(ticket)});
		return id;
	}

	/* The next id above the last, starting over at 1 after m_maxId and
	 * skipping jobs not yet delivered. */
	JobId NextId()
	{
		do {
			m_lastId = m_lastId >= m_maxId ? 1 : m_lastId + 1;
		} while (m_pending.count(m_lastId) != 0);
		return m_lastId;
	}

	template <typename Deliver>
	void DeliverOne(JobId id, FileHashOutcome outcome, Deliver &deliver)
	{
		auto found = m_pending.find(id);
		if (found == m_pending.end())
			return;
		EndedJob ended{id, std::move(found->second.owner), std::move(found->second.ticket), std::move(outcome)};
		m_pending.erase(found);
		deliver(std::move(ended));
	}

	const JobId m_maxId;
	JobId m_lastId = 0;
	std::map<JobId, Pending> m_pending;
	std::vector<JobId> m_refused;
	/* Last, so it is stopped before the jobs it reports on are gone. */
	Worker m_worker;
};

} // namespace smcrypto

#endif // SMCRYPTO_CORE_FILE_JOBS_H
