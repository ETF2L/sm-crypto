/* Copyright 2026 ETF2L Contributors, Dave
 *
 * The byte containers of the core: Bytes for public data, SecretBytes for
 * keys and plaintexts, whose memory is wiped whenever it is released (also
 * when the vector grows), and ByteView, a non-owning view of either. */
#ifndef SMCRYPTO_CORE_BYTES_H
#define SMCRYPTO_CORE_BYTES_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace smcrypto {

/* Overwrites size bytes so the compiler cannot drop the write. */
void Wipe(void *data, size_t size);

/* An allocator that wipes every block before it is freed. */
template <typename T>
struct WipingAllocator {
	using value_type = T;

	WipingAllocator() = default;
	template <typename U>
	WipingAllocator(const WipingAllocator<U> &) noexcept
	{
	}

	T *allocate(size_t count) { return std::allocator<T>().allocate(count); }

	void deallocate(T *block, size_t count) noexcept
	{
		Wipe(block, count * sizeof(T));
		std::allocator<T>().deallocate(block, count);
	}

	template <typename U>
	bool operator==(const WipingAllocator<U> &) const noexcept
	{
		return true;
	}
	template <typename U>
	bool operator!=(const WipingAllocator<U> &) const noexcept
	{
		return false;
	}
};

using Bytes = std::vector<uint8_t>;
using SecretBytes = std::vector<uint8_t, WipingAllocator<uint8_t>>;

/* A view of bytes owned elsewhere. */
struct ByteView {
	const uint8_t *data = nullptr;
	size_t size = 0;

	ByteView() = default;
	ByteView(const uint8_t *viewData, size_t viewSize) : data(viewData), size(viewSize) {}
	ByteView(const Bytes &bytes) : data(bytes.data()), size(bytes.size()) {}
	ByteView(const SecretBytes &bytes) : data(bytes.data()), size(bytes.size()) {}
	ByteView(const std::string &text) : data(reinterpret_cast<const uint8_t *>(text.data())), size(text.size()) {}

	bool empty() const { return size == 0; }
};

/* Compares two views in time that depends only on their sizes. */
bool ConstantTimeEqual(ByteView a, ByteView b);

} // namespace smcrypto

#endif // SMCRYPTO_CORE_BYTES_H
