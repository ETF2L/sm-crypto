/* Copyright 2026 ETF2L Contributors, Dave */
#include "extension.h"

#include "library.h"

#include <new>

using namespace smcrypto;

SMCrypto g_SMCrypto;
SMEXT_LINK(&g_SMCrypto);

namespace {

void OnGameFrame(bool simulating)
{
	g_SMCrypto.OnFrame();
}

} // namespace

bool SMCrypto::CreateHandleTypes(char *error, size_t maxlength)
{
	/* Only the plugin that owns a key or digest may use it, and nobody may
	 * clone it: SourceMod's CloneHandle passes no owner to check, so a
	 * clone could otherwise be taken by any plugin that guesses the handle. */
	HandleAccess access;
	handlesys->InitAccessDefaults(nullptr, &access);
	access.access[HandleAccess_Read] |= HANDLE_RESTRICT_OWNER;
	access.access[HandleAccess_Clone] |= HANDLE_RESTRICT_OWNER;

	struct NamedType {
		const char *name;
		HandleType_t *type;
	};
	const NamedType types[] = {
		{"CryptoKey", &keyType},
		{"CryptoDigest", &digestType},
	};
	for (const NamedType &named : types) {
		HandleError handleError;
		*named.type = handlesys->CreateType(named.name, this, 0, nullptr, &access, myself->GetIdentity(),
		                                    &handleError);
		if (*named.type == 0) {
			snprintf(error, maxlength, "cannot create the handle type %s (error %d)", named.name, handleError);
			return false;
		}
	}
	return true;
}

void SMCrypto::RemoveHandleTypes()
{
	/* Removing a type frees its handles: keys are wiped, digests release
	 * their library state. */
	for (HandleType_t *type : {&keyType, &digestType}) {
		if (*type != 0)
			handlesys->RemoveType(*type, myself->GetIdentity());
		*type = 0;
	}
}

bool SMCrypto::SDK_OnLoad(char *error, size_t maxlength, bool late)
{
	Status started = InitializeLibrary();
	if (!started.IsOk()) {
		snprintf(error, maxlength, "%s could not start: %s", LibraryVersion(), started.Error().Describe().c_str());
		return false;
	}
	m_isLibraryStarted = true;
	/* SourceMod does not unload an extension whose load failed. */
	if (!CreateHandleTypes(error, maxlength)) {
		SDK_OnUnload();
		return false;
	}
	m_jobs = std::make_unique<PluginFileJobs>();
	sharesys->AddNatives(myself, g_CryptoNatives);
	sharesys->AddNatives(myself, g_KeyNatives);
	sharesys->AddNatives(myself, g_DigestNatives);
	sharesys->RegisterLibrary(myself, "smcrypto");
	plsys->AddPluginsListener(this);
	smutils->AddGameFrameHook(OnGameFrame);
	m_isHooked = true;
	return true;
}

void SMCrypto::SDK_OnUnload()
{
	if (m_isHooked) {
		smutils->RemoveGameFrameHook(OnGameFrame);
		plsys->RemovePluginsListener(this);
		m_isHooked = false;
	}
	m_jobs.reset();
	RemoveHandleTypes();
	if (m_isLibraryStarted)
		ShutdownLibrary();
	m_isLibraryStarted = false;
}

void SMCrypto::OnPluginUnloaded(IPlugin *plugin)
{
	m_jobs->DropOwner(JobOwner(plugin->GetBaseContext()));
}

void SMCrypto::OnHandleDestroy(HandleType_t type, void *object)
{
	if (type == keyType)
		delete static_cast<KeyObject *>(object);
	else if (type == digestType)
		delete static_cast<DigestObject *>(object);
}

void SMCrypto::OnFrame()
{
	if (!m_jobs)
		return;
	/* Runs in SourceMod's frame hook, which no exception may leave. */
	try {
		m_jobs->DeliverEnded([this](PluginFileJobs::EndedJob &&job) { Deliver(job); });
	} catch (const std::bad_alloc &) {
		smutils->LogError(myself, "File job callbacks wait for a later frame: out of memory");
	}
}

void SMCrypto::Deliver(const PluginFileJobs::EndedJob &job)
{
	const FileJobTicket &ticket = job.ticket;
	const FileHashOutcome &outcome = job.outcome;
	CryptoError error = CryptoErrorOf(outcome.error);

	/* The digest as a binary string with its NUL: Raw digests may hold
	 * NULs. When memory runs out here, the job is told as Internal with an
	 * empty digest rather than lost, and no exception leaves the frame. */
	SecretBytes digest;
	try {
		if (outcome.library)
			smutils->LogError(myself, "Hashing \"%s\" failed: %s", ticket.path.c_str(),
			                  outcome.library->Describe().c_str());
		else if (error == CryptoError::Internal)
			smutils->LogError(myself, "Hashing \"%s\" failed: out of memory", ticket.path.c_str());
		digest = Encode(outcome.digest, ticket.encoding);
		digest.push_back(0);
	} catch (const std::bad_alloc &) {
		smutils->LogError(myself, "Hashing \"%s\": out of memory before its callback", ticket.path.c_str());
		error = CryptoError::Internal;
		digest.clear();
	}
	static char kNoDigest[] = "";
	char *digestText = digest.empty() ? kNoDigest : reinterpret_cast<char *>(digest.data());
	size_t digestSize = digest.empty() ? sizeof(kNoDigest) : digest.size();
	cell_t digestLength = static_cast<cell_t>(digestSize - 1);

	IPluginFunction *function = nullptr;
	if (!job.owner.m_context->GetFunctionByIdOrNull(ticket.callback, &function) || !function)
		return;
	function->PushCell(static_cast<cell_t>(job.id));
	function->PushCell(static_cast<cell_t>(error));
	function->PushString(ticket.path.c_str());
	function->PushStringEx(digestText, digestSize, SM_PARAM_STRING_BINARY | SM_PARAM_STRING_COPY, 0);
	function->PushCell(digestLength);
	function->PushCell(ticket.data);
	function->Execute(nullptr);
}
