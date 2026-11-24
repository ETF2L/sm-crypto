/* Copyright 2026 ETF2L Contributors, Dave */
#include "bytes.h"

namespace smcrypto {

/* Wipe() is in library.cpp, with the library's other non-PSA calls. */

bool ConstantTimeEqual(ByteView a, ByteView b)
{
	if (a.size != b.size)
		return false;
	/* volatile keeps the compiler from ending the loop at the first
	 * difference. */
	volatile uint8_t difference = 0;
	for (size_t i = 0; i < a.size; i++)
		difference = static_cast<uint8_t>(difference | (a.data[i] ^ b.data[i]));
	return difference == 0;
}

} // namespace smcrypto
