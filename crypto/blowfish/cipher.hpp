#pragma once

#include "crypto/blowfish/s_box.hpp"

#include "datum/bytes.hpp"

namespace WarGrey::DTPM {
	private class BlowfishCipher {
	public:
		BlowfishCipher(const uint8* key, size_t ksize);

	public:
		size_t encrypt(const uint8* plaintext, size_t pstart, size_t pend, uint8* ciphertext, size_t cstart, size_t cend);
		size_t decrypt(const uint8* ciphertext, size_t cstart, size_t cend, uint8* plaintext, size_t pstart, size_t pend);

	private:
		WarGrey::DTPM::BFBox box;
	};

	private class BlowfishCipherCBC {
	public:
		BlowfishCipherCBC(const uint8* IV, const uint8* key, size_t ksize);

	public:
		size_t encrypt(const uint8* plaintext, size_t pstart, size_t pend, uint8* ciphertext, size_t cstart, size_t cend);
		size_t decrypt(const uint8* ciphertext, size_t cstart, size_t cend, uint8* plaintext, size_t pstart, size_t pend);

	private:
		WarGrey::DTPM::BFBox box;
		uint32 cbcL;
		uint32 cbcR;
	};
}
