/* Copyright 2026 ETF2L Contributors, Dave */
#include "natives_common.h"

#include "paths.h"

#include <cstdint>
#include <exception>
#include <limits>
#include <new>

using namespace smcrypto;

namespace natives {

namespace {

/* The stack pointer params belongs to, or nothing when params is not in
 * the plugin's memory (a native called by other code than the VM). */
std::optional<int64_t> StackPointerOf(IPluginContext *context, const cell_t *params)
{
	cell_t *base = nullptr;
	if (context->LocalToPhysAddr(0, &base) != SP_ERROR_NONE)
		return std::nullopt;
	int64_t offset = reinterpret_cast<const uint8_t *>(params) - reinterpret_cast<const uint8_t *>(base);
	bool isInMemory = offset >= 0 && offset <= std::numeric_limits<cell_t>::max() &&
	                  context->LocalToPhysAddr(static_cast<cell_t>(offset), nullptr) == SP_ERROR_NONE;
	return isInMemory ? std::optional<int64_t>(offset) : std::nullopt;
}

} // namespace

SourcePawnPlugin::SourcePawnPlugin(IPluginContext *context, const cell_t *params)
	: m_context(context), m_stackPointer(StackPointerOf(context, params))
{
}

uint8_t *SourcePawnPlugin::Resolve(cell_t address)
{
	cell_t *physical = nullptr;
	if (m_context->LocalToPhysAddr(address, &physical) != SP_ERROR_NONE)
		return nullptr;
	return reinterpret_cast<uint8_t *>(physical);
}

std::optional<int64_t> SourcePawnPlugin::StackPointer() const
{
	return m_stackPointer;
}

void SourcePawnPlugin::ReportError(const char *message)
{
	m_context->ReportError("%s", message);
}

PluginCall::PluginCall(SourcePawnPlugin &plugin, const cell_t *params)
	: NativeCall(plugin, params), m_context(plugin.m_context)
{
}

void *PluginCall::ReadObject(int index, HandleType_t type, const char *typeName)
{
	cell_t handle = Arg(index);
	HandleSecurity security(m_context->GetIdentity(), myself->GetIdentity());
	void *object = nullptr;
	HandleError error = handlesys->ReadHandle(static_cast<Handle_t>(handle), type, &security, &object);
	if (error != HandleError_None) {
		Fail("Invalid %s handle %x (error %d)", typeName, handle, error);
		return nullptr;
	}
	return object;
}

KeyObject *PluginCall::ReadKey(int index)
{
	return static_cast<KeyObject *>(ReadObject(index, g_SMCrypto.keyType, "CryptoKey"));
}

DigestObject *PluginCall::ReadDigest(int index)
{
	return static_cast<DigestObject *>(ReadObject(index, g_SMCrypto.digestType, "CryptoDigest"));
}

bool PluginCall::ReadCallback(int index, funcid_t &function)
{
	cell_t value = Arg(index);
	IPluginFunction *found = nullptr;
	/* GetFunctionByIdOrNull throws the native error of an invalid id itself. */
	if (!m_context->GetFunctionByIdOrNull(static_cast<funcid_t>(value), &found))
		return false;
	if (!found)
		return Fail("Invalid callback function %x", value);
	function = static_cast<funcid_t>(value);
	return true;
}

bool PluginCall::ReadGamePath(int index, std::string &given, std::string &resolved, bool &isAllowed)
{
	ByteView text;
	if (!ReadText(index, "path", text))
		return false;
	given.assign(reinterpret_cast<const char *>(text.data), text.size);
	isAllowed = false;
	if (!IsGameRelativePath(given))
		return true;
	char buffer[PLATFORM_MAX_PATH];
	size_t length = smutils->BuildPath(Path_Game, buffer, sizeof(buffer), "%s", given.c_str());
	if (length + 1 >= sizeof(buffer))
		return true;
	resolved = buffer;
	isAllowed = true;
	return true;
}

cell_t PluginCall::CreateHandle(HandleType_t type, void *object)
{
	HandleError error;
	Handle_t handle = handlesys->CreateHandle(type, object, m_context->GetIdentity(), myself->GetIdentity(), &error);
	if (handle == BAD_HANDLE) {
		g_SMCrypto.OnHandleDestroy(type, object);
		Fail("Cannot create a handle (error %d)", error);
		return 0;
	}
	return static_cast<cell_t>(handle);
}

void ReportException(IPluginContext *context)
{
	try {
		throw;
	} catch (const std::bad_alloc &) {
		context->ReportError("SMCrypto ran out of memory");
	} catch (const std::exception &exception) {
		context->ReportError("SMCrypto failed: %s", exception.what());
	} catch (...) {
		context->ReportError("SMCrypto failed with an unknown exception");
	}
}

} // namespace natives
