#pragma once

#include "crypto/blowfish/pi_box.hpp"

namespace WarGrey::DTPM {
	private struct BFBox {
		uint32 parray[sizeof(parray) / sizeof(uint32)];
		uint32 sbox[sizeof(sbox) / sizeof(uint32)];
	};

	void blowfish_initiate_boxes(const uint8* key, size_t size, WarGrey::DTPM::BFBox* box);
}
