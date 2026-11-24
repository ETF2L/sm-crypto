/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The SourceMod side of a native call: the calling plugin over SourcePawn
 * for the core's NativeCall, which reads every argument and checks every
 * span of plugin memory, and what only SourceMod has: handles, callbacks
 * and paths below the game directory. A native gets nothing but its
 * PluginCall, so it cannot reach the plugin's memory around those checks.
 * Each reader returns false after throwing a native error; the native then
 * returns at once. */
#ifndef SMCRYPTO_NATIVES_COMMON_H
#define SMCRYPTO_NATIVES_COMMON_H

#include "extension.h"

#include "native_call.h"

#include <optional>
#include <string>
#include <type_traits>

namespace natives {

static_assert(std::is_same<cell_t, smcrypto::Cell>::value, "a plugin's cell is SourcePawn's cell_t");

/* Bytes in plugin memory; valid until the plugin runs again. */
using smcrypto::ByteView;

/* The plugin that called a native, through its SourcePawn context. Its
 * stack pointer is where params lies: SourcePawn passes a native's
 * arguments on top of the plugin's stack. */
class SourcePawnPlugin : public smcrypto::CallingPlugin {
public:
	SourcePawnPlugin(IPluginContext *context, const cell_t *params);

	uint8_t *Resolve(cell_t address) override;
	std::optional<int64_t> StackPointer() const override;
	void ReportError(const char *message) override;

private:
	friend class PluginCall;

	IPluginContext *m_context;
	std::optional<int64_t> m_stackPointer;
};

class PluginCall : public smcrypto::NativeCall {
public:
	PluginCall(SourcePawnPlugin &plugin, const cell_t *params);

	/* The calling plugin as the job owner of the file jobs it queues. */
	JobOwner Owner() const { return JobOwner(m_context); }

	/* The object of the handle in argument index, or nullptr after a
	 * native error. */
	KeyObject *ReadKey(int index);
	DigestObject *ReadDigest(int index);

	/* A callback argument that must be a function. */
	bool ReadCallback(int index, funcid_t &function);

	/* The path in argument index for a file job, as given and resolved
	 * below the game directory. isAllowed is false, and no native error
	 * thrown, when it breaks the path rule or is too long: a path may come
	 * from a file name nobody checked. */
	bool ReadGamePath(int index, std::string &given, std::string &resolved, bool &isAllowed);

	/* A new handle owned by the calling plugin, taking object; 0 after a
	 * native error (object is then destroyed). */
	cell_t CreateHandle(HandleType_t type, void *object);

private:
	void *ReadObject(int index, HandleType_t type, const char *typeName);

	IPluginContext *m_context;
};

/* Throws the native error of an exception that left a native: no
 * exception may unwind through the VM's frames. */
void ReportException(IPluginContext *context);

/* A native that first checks that it got count arguments, for the native
 * tables: {"Crypto.Hash", Checked<6, Crypto_Hash>}. Every native goes
 * through it. An exception, such as an allocation that fails, becomes a
 * native error. */
template <cell_t count, cell_t (*native)(PluginCall &)>
cell_t Checked(IPluginContext *context, const cell_t *params)
{
	SourcePawnPlugin plugin(context, params);
	PluginCall call(plugin, params);
	try {
		if (!call.HasArguments(count))
			return 0;
		return native(call);
	} catch (...) {
		ReportException(context);
		return 0;
	}
}

} // namespace natives

#endif // SMCRYPTO_NATIVES_COMMON_H
