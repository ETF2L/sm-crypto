/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The SourceMod side of SMCrypto: the handle types of keys and digests, and
 * the frame hook that calls the callbacks of the file jobs plugins queued.
 * Everything here runs on the main thread; the core's worker thread only
 * hashes files. */
#ifndef SMCRYPTO_EXTENSION_H
#define SMCRYPTO_EXTENSION_H

#include "smsdk_ext.h"

#include "bytes.h"
#include "crypto_error.h"
#include "digest.h"
#include "encoding.h"
#include "file_jobs.h"

#include <memory>
#include <string>

/* What a CryptoKey handle holds; the handle cannot be cloned. */
struct KeyObject {
	smcrypto::SecretBytes bytes;
};

/* What a CryptoDigest handle holds. */
struct DigestObject {
	std::unique_ptr<smcrypto::Digest> digest;
};

/* What a file job needs to call its plugin back. */
struct FileJobTicket {
	funcid_t callback = 0;
	cell_t data = 0;
	smcrypto::Encoding encoding = smcrypto::Encoding::Hex;
	std::string path; /* as the plugin passed it */
};

namespace natives {
class PluginCall;
}

/* The job owner of a file job, the plugin that queued it: a token only
 * SMCrypto turns back into the plugin, for its callbacks. */
class JobOwner {
public:
	bool operator==(const JobOwner &other) const { return m_context == other.m_context; }

private:
	friend class SMCrypto;
	friend class natives::PluginCall;

	explicit JobOwner(IPluginContext *context) : m_context(context) {}

	IPluginContext *m_context;
};

/* The file jobs of the plugins. */
using PluginFileJobs = smcrypto::FileJobs<JobOwner, FileJobTicket>;

class SMCrypto : public SDKExtension, public IPluginsListener, public IHandleTypeDispatch {
public: // SDKExtension
	bool SDK_OnLoad(char *error, size_t maxlength, bool late) override;
	void SDK_OnUnload() override;

public: // IPluginsListener
	void OnPluginUnloaded(IPlugin *plugin) override;

public: // IHandleTypeDispatch
	void OnHandleDestroy(HandleType_t type, void *object) override;

public:
	/* The file jobs; only while the extension is loaded. */
	PluginFileJobs &Jobs() { return *m_jobs; }

	/* Calls the callbacks of the jobs that ended since the last frame. */
	void OnFrame();

	HandleType_t keyType = 0;
	HandleType_t digestType = 0;

private:
	bool CreateHandleTypes(char *error, size_t maxlength);
	void RemoveHandleTypes();
	void Deliver(const PluginFileJobs::EndedJob &job);

	std::unique_ptr<PluginFileJobs> m_jobs;
	bool m_isLibraryStarted = false;
	bool m_isHooked = false;
};

extern SMCrypto g_SMCrypto;

/* The natives, one table per file. */
extern const sp_nativeinfo_t g_CryptoNatives[];
extern const sp_nativeinfo_t g_KeyNatives[];
extern const sp_nativeinfo_t g_DigestNatives[];

#endif // SMCRYPTO_EXTENSION_H
