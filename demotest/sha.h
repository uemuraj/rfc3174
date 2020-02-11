#pragma once

#if !defined(__cpp_inline_variables)
#error
#endif

#include <stdint.h>

extern "C" {
#include "sha1.h"
}

struct Sha1 : SHA1Context
{
	constexpr static size_t HASH_SIZE = SHA1HashSize;

	Sha1()
	{
		SHA1Reset(this);
	}

	int input(const uint8_t * message, size_t length)
	{
		return SHA1Input(this, message, (unsigned int) length);
	}

	int result(uint8_t(&digest)[HASH_SIZE])
	{
		return SHA1Result(this, digest);
	}
};
