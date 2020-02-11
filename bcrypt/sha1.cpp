#define _WIN32_WINNT _WIN32_WINNT_WIN7
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <bcrypt.h>
#pragma comment (lib, "bcrypt")

#include <vector>
#include <iostream>
#include <iomanip>

class SHA1
{
	BCRYPT_ALG_HANDLE m_algorithm;

	BCRYPT_HASH_HANDLE m_hash;

	NTSTATUS m_status;

	std::vector<uint8_t> m_object;

	std::vector<uint8_t> m_value;

public:
	SHA1(const uint8_t * data, unsigned int size) : m_algorithm(nullptr), m_hash(nullptr), m_status(::BCryptOpenAlgorithmProvider(&m_algorithm, BCRYPT_SHA1_ALGORITHM, nullptr, 0))
	{
		ULONG length{};
		ULONG result{};

		if (m_status == 0)
		{
			m_status = ::BCryptGetProperty(m_algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR) &length, sizeof(length), &result, 0);
		}

		m_object.resize(length);

		if (m_status == 0)
		{
			m_status = ::BCryptCreateHash(m_algorithm, &m_hash, &m_object[0], length, nullptr, 0, 0);
		}

		if (m_status == 0)
		{
			m_status = ::BCryptGetProperty(m_algorithm, BCRYPT_HASH_LENGTH, (PUCHAR) &length, sizeof(length), &result, 0);
		}

		m_value.resize(length);

		if (m_status == 0)
		{
			m_status = ::BCryptHashData(m_hash, const_cast<PUCHAR>(data), size, 0);
		}

		if (m_status == 0)
		{
			m_status = ::BCryptFinishHash(m_hash, &m_value[0], length, 0);
		}
	}

	~SHA1()
	{
		::BCryptCloseAlgorithmProvider(m_algorithm, 0);
	}

	operator bool()
	{
		return m_status == 0;
	}

	template <class char_type>
	std::basic_ostream<char_type> & print(std::basic_ostream<char_type> & os) const
	{
		auto fmt = os.flags();

		os.flags(std::ios_base::hex | std::ios_base::uppercase);

		for (const auto & value : m_value)
		{
			os << std::setw(2) << std::setfill('0') << (int) value << ' ';
		}

		os.flags(fmt);

		return os;
	}
};

template <class char_type>
std::basic_ostream<char_type> & operator<<(std::basic_ostream<char_type> & os, const SHA1 & sha1)
{
	return sha1.print(os);
}

/*
  *  Define patterns for testing
  */
#define TEST1   "abc"
#define TEST2a  "abcdbcdecdefdefgefghfghighijhi"
#define TEST2b  "jkijkljklmklmnlmnomnopnopq"
#define TEST2   TEST2a TEST2b
#define TEST3   "a"
#define TEST4a  "01234567012345670123456701234567"
#define TEST4b  "01234567012345670123456701234567"
  /* an exact multiple of 512 bits */
#define TEST4   TEST4a TEST4b

const char * testarray[4] =
{
	TEST1,
	TEST2,
	TEST3,
	TEST4
};

int main()
{
	std::cout << SHA1((const uint8_t *) testarray[0], (unsigned int) strlen(testarray[0]));

	return 0;
}
