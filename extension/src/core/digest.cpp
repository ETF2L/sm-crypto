/* Copyright 2026 ETF2L Contributors, Dave */
#include "digest.h"

namespace smcrypto {

Digest::Digest(Hash hash, std::unique_ptr<HashStream> hashStream, std::unique_ptr<MacStream> macStream)
	: m_hash(hash), m_plain(std::move(hashStream)), m_mac(std::move(macStream))
{
}

Result<std::unique_ptr<Digest>> Digest::StartHash(Hash hash)
{
	Result<std::unique_ptr<HashStream>> stream = HashStream::Start(hash);
	if (!stream.IsOk())
		return stream.Error();
	return std::unique_ptr<Digest>(new Digest(hash, std::move(stream.Value()), nullptr));
}

Result<std::unique_ptr<Digest>> Digest::StartHmac(Hash hash, ByteView key)
{
	Result<std::unique_ptr<MacStream>> stream = MacStream::Start(hash, key);
	if (!stream.IsOk())
		return stream.Error();
	return std::unique_ptr<Digest>(new Digest(hash, nullptr, std::move(stream.Value())));
}

Status Digest::Update(ByteView data)
{
	Status updated = m_mac ? m_mac->Update(data) : m_plain->Update(data);
	/* A stream that failed takes no more; telling it finished keeps plugins
	 * from getting a second error from it that blames the library. */
	m_isFinished = !updated.IsOk();
	return updated;
}

Result<Bytes> Digest::Finish()
{
	m_isFinished = true;
	return m_mac ? m_mac->Finish() : m_plain->Finish();
}

} // namespace smcrypto
