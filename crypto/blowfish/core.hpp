#pragma once

#include "crypto/blowfish/pi_box.hpp"

namespace WarGrey::DTPM {
	void bf_encrypt(uint32 pL, uint32 pR, const uint32* P, const uint32* S, uint32* cL, uint32* cR);
	void bf_decrypt(uint32 cL, uint32 cR, const uint32* P, const uint32* S, uint32* pL, uint32* pR);
}
