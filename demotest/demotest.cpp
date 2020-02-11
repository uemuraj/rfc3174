/*
 *  demotest.cpp
 */
#include "sha.h"

/*
 *  Define patterns for testing
 */
const char * testarray[] =
{
	"abc",
	"abcdbcdecdefdefgefghfghighijhi" "jkijkljklmklmnlmnomnopnopq",
	"a",
	"01234567012345670123456701234567" "01234567012345670123456701234567",
};

long int repeatcount[] = { 1, 1, 1000000, 10 };

const char * resultarray[] =
{
	"A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D",
	"84 98 3E 44 1C 3B D2 6E BA AE 4A A1 F9 51 29 E5 E5 46 70 F1",
	"34 AA 97 3C D4 C4 DA A4 F6 1E EB 2B DB AD 27 31 65 34 01 6F",
	"DE A3 56 A2 CD DD 90 C7 A7 EC ED C5 EB B5 63 93 4F 46 04 52",
};

#include <cassert>
#include <cstring>
#include <sstream>
#include <iomanip>

std::string digest_to_string(const uint8_t(&digest)[Sha1::HASH_SIZE])
{
	std::ostringstream oss;

	oss.flags(std::ios_base::hex | std::ios_base::uppercase);

	for (int value : digest)
	{
		oss << std::setw(2) << std::setfill('0') << value << ' ';
	}

	auto str = oss.str();

	str.pop_back();

	return str;
}

int main()
{
	for (auto & message : testarray)
	{
		auto j = &message - &testarray[0];

		Sha1 sha1;

		for (int i = 0; i < repeatcount[j]; i++)
		{
			auto err = sha1.input((const uint8_t *) message, std::strlen(message));
			assert(err == shaSuccess);
		}

		uint8_t digest[Sha1::HASH_SIZE]{};

		auto err = sha1.result(digest);
		assert(err == shaSuccess);

		auto str = digest_to_string(digest);
		assert(str.compare(resultarray[j]) == 0);
	}

	return 0;
}
