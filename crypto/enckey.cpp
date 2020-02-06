#include "crypto/enckey.hpp"
#include "crypto/blowfish.hpp"
#include "crypto/checksum.hpp"

#include "datum/string.hpp"
#include "datum/bytes.hpp"

using namespace WarGrey::SCADA;
using namespace WarGrey::GYDM;

/**************************************************************************************************/
template<typename B>
static Natural bytes_to_natural(B* bs, size_t digit_count, size_t start) {
	size_t end = start + digit_count;
	Natural id(0U);

	for (size_t idx = 0; idx < digit_count; idx++) {
		uint8 digit = byte_to_hexadecimal(bs[start + idx], 0U);

		id <<= 8U;
		id += hexadecimal_to_byte(digit);
	}

	return id;
}

/**************************************************************************************************/
Natural WarGrey::DTPM::enc_natural(uint64 literal_id) {
	Natural n;
	uint8 idx = 0;

	while (literal_id > 0U) {
		uint8 digit = literal_id & 0xFU;
		size_t shift = n.length() * 8U;

		n ^= ((uint64)(hexadecimal_to_byte(digit)) << shift);

		literal_id >>= 4U;
	}

	return n;
}

Natural WarGrey::DTPM::enc_natural(const char* literal_id, size_t digit_count, size_t start) {
	return bytes_to_natural(literal_id, digit_count, start);
}

Natural WarGrey::DTPM::enc_natural(bytes& literal_id, size_t start) {
	return bytes_to_natural(literal_id.c_str(), literal_id.size() - start, start);
}

Natural WarGrey::DTPM::enc_natural(std::string& literal_id, size_t start) {
	return bytes_to_natural(literal_id.c_str(), literal_id.size() - start, start);
}

/**************************************************************************************************/
bytes WarGrey::DTPM::enc_ascii(uint64 id) {
	return enc_natural(id).to_hexstring();
}

bytes WarGrey::DTPM::enc_ascii(Natural& id) {
	return id.to_hexstring();
}

Natural WarGrey::DTPM::enc_natural_from_ascii(const char* ascii, size_t digit_count, size_t start) {
	return Natural(16U, (const uint8*)ascii, start, start + digit_count * 2U);
}

Natural WarGrey::DTPM::enc_natural_from_ascii(bytes& literal_id, size_t digit_count, size_t start) {
	return Natural(16U, literal_id.c_str(), start, start + digit_count * 2U);
}

Natural WarGrey::DTPM::enc_natural_from_ascii(std::string& literal_id, size_t digit_count, size_t start) {
	return enc_natural_from_ascii(literal_id.c_str(), digit_count, start);
}

/**************************************************************************************************/
Natural WarGrey::DTPM::enc_hardware_uid6(Natural HW_ID) {
	return HW_ID[0] ^ (HW_ID << 8U);
}

Natural WarGrey::DTPM::enc_natural_pad(Natural n) {
	size_t size = n.length();
	size_t remainder = size % 8;
	
	if (remainder > 0) {
		size_t padsize = 8 - remainder;

		for (uint8 idx = 0; idx < padsize; idx++) {
			n <<= 8U;
			n += padsize;
		}
	}

	return n;
}

Natural WarGrey::DTPM::enc_natural_unpad(Natural n) {
	n >>= (8U * n[-1]);

	return n;
}

/**************************************************************************************************/
Natural WarGrey::DTPM::enc_cell_permit_encrypt(const Natural& HW_ID, const Natural& ck) {
	const size_t key_size = 8U;
	uint8 cipher[key_size];
	Natural HW_ID6 = enc_hardware_uid6(HW_ID);
	BlowfishCipher bf(HW_ID6.to_bytes().c_str(), HW_ID6.length());
	size_t key_remainder = ck.length() % 8U;

	if (key_remainder > 0U) {
		bf.encrypt(enc_natural_pad(ck).to_bytes().c_str(), 0U, key_size, cipher, 0U, key_size);
	} else {
		bf.encrypt(ck.to_bytes().c_str(), 0U, key_size, cipher, 0U, key_size);
	}

	return Natural(cipher);
}

Natural WarGrey::DTPM::enc_cell_permit_decrypt(const Natural& HW_ID, const Natural& eck) {
	const size_t key_size = 8U;
	uint8 plain[key_size];
	Natural HW_ID6 = enc_hardware_uid6(HW_ID);
	BlowfishCipher bf(HW_ID6.to_bytes().c_str(), HW_ID6.length());
	size_t key_remainder = eck.length() % 8U;

	if (key_remainder > 0U) {
		bf.decrypt(enc_natural_pad(eck).to_bytes().c_str(), 0U, key_size, plain, 0U, key_size);
	} else {
		bf.decrypt(eck.to_bytes().c_str(), 0U, key_size, plain, 0U, key_size);
	}

	return enc_natural_unpad(Natural(plain));
}

Natural WarGrey::DTPM::enc_cell_permit_checksum(const char* name, size_t nsize, uint32 expiry_date, const Natural& eck1, const Natural& eck2) {
	std::string date = make_nstring("%d", expiry_date);
	unsigned long CRC = 0U;

	checksum_crc32(&CRC, (const uint8*)name, 0U, nsize);
	checksum_crc32(&CRC, (const uint8*)date.c_str(), 0U, date.length());
	checksum_crc32(&CRC, eck1.to_hexstring().c_str(), 0U, eck1.length() * 2U);
	checksum_crc32(&CRC, eck2.to_hexstring().c_str(), 0U, eck2.length() * 2U);

	return Natural(CRC);
}

Natural WarGrey::DTPM::enc_cell_permit_checksum(const Natural& HW_ID, const char* name, size_t nsize, uint32 expiry_date, const Natural& ck1, const Natural& ck2) {
	Natural eck1 = enc_cell_permit_encrypt(HW_ID, ck1);
	Natural eck2 = enc_cell_permit_encrypt(HW_ID, ck2);
	Natural CRC = enc_cell_permit_checksum(name, nsize, expiry_date, eck1, eck2);

	return enc_cell_permit_encrypt(HW_ID, CRC);
}

Natural WarGrey::DTPM::enc_cell_permit_checksum(const char* name, size_t nsize
	, uint32 expiry_year, uint32 expiry_month, uint32 expiry_day, const Natural& eck1, const Natural& eck2) {
	return enc_cell_permit_checksum(name, nsize, expiry_year * 10000U + expiry_month * 100U + expiry_day, eck1, eck2);
}

Natural WarGrey::DTPM::enc_cell_permit_checksum(const Natural& HW_ID, const char* name, size_t nsize
	, uint32 expiry_year, uint32 expiry_month, uint32 expiry_day, const Natural& ck1, const Natural& ck2) {
	return enc_cell_permit_checksum(HW_ID, name, nsize, expiry_year * 10000U + expiry_month * 100U + expiry_day, ck1, ck2);
}
